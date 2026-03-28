#!/usr/bin/env python3
"""
tailscale.py  —  NetScope: Home Network Dashboard
==================================================

A live home network scanner served as a local web app.
Run this, then open it from any device on your Tailscale network.

No Tailscale-specific code here — Tailscale handles the networking
transparently. This is just a web server that binds to 0.0.0.0.

Requirements:
    pip install flask

Usage:
    python tailscale.py
    Then open http://<your-tailscale-ip>:5500 on any tailnet device.
"""

import concurrent.futures
import ipaddress
import json
import os
import socket
import subprocess
import threading
import time
from datetime import datetime

import flask
from flask import Flask, Response, stream_with_context

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

PORT = 5500

# Scanner tuning
TOP_PORTS    = 150   # how many common ports to probe per host
TCP_TIMEOUT  = 0.4   # seconds per TCP connect attempt
PORT_WORKERS = 80    # parallel port probes per host
HOST_WORKERS = 10    # parallel host deep-scans

# ─────────────────────────────────────────────────────────────────────────────
# Port lists and names
# ─────────────────────────────────────────────────────────────────────────────

COMMON_PORTS = list(dict.fromkeys([
    80, 443, 22, 21, 25, 3389, 110, 143, 53, 8080,
    8443, 8888, 3306, 5432, 1433, 27017, 6379, 11211, 9200, 5601,
    23, 69, 161, 162, 514, 389, 636, 88, 445, 139,
    135, 137, 138, 5985, 5986, 9090, 9091, 4848, 8009, 4444,
    1080, 1194, 1723, 500, 4500, 1900, 5353, 5000, 5001, 8081,
    8082, 8083, 8090, 3000, 3001, 4000, 4001, 6000, 6001, 7000,
    7001, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008,
    2049, 111, 2121, 990, 993, 995, 587, 465, 2525, 1025,
    1521, 5984, 7474, 9300, 15672, 5672, 4369, 61616, 8161, 61613,
    6443, 2379, 2380, 10250, 10255, 30000, 32000, 2375, 2376,
    7199, 9042, 9160, 8086, 8087, 1883, 8883, 5683,
    502, 102, 20000, 44818, 5900, 5901, 5902, 5903, 6881, 6969,
    7070, 8554, 9001, 9002, 9003, 32400, 8096, 8920, 51413,
]))[:TOP_PORTS]

PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC", 135: "MS-RPC",
    137: "NetBIOS-NS", 138: "NetBIOS-DG", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "SMTP-Submit", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle DB", 1723: "PPTP", 1883: "MQTT",
    2049: "NFS", 2375: "Docker", 2376: "Docker-TLS", 2379: "etcd",
    3000: "Dev / Grafana", 3306: "MySQL", 3389: "RDP", 5000: "UPnP / Dev",
    5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    6443: "Kubernetes API", 7474: "Neo4j", 8080: "HTTP-alt",
    8096: "Jellyfin", 8443: "HTTPS-alt", 8888: "Jupyter / HTTP",
    9000: "SonarQube", 9090: "Prometheus", 9200: "Elasticsearch",
    10250: "Kubelet", 11211: "Memcached", 15672: "RabbitMQ Mgmt",
    27017: "MongoDB", 32400: "Plex", 44818: "EtherNet/IP",
}


# ─────────────────────────────────────────────────────────────────────────────
# Network scanner — Python stdlib only
# ─────────────────────────────────────────────────────────────────────────────

def get_local_subnet() -> str:
    """
    Determine this PC's LAN subnet by finding the outbound interface IP,
    then deriving a /24 range. E.g. 192.168.1.42 → 192.168.1.0/24.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return f"{ip.rsplit('.', 1)[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def ping_host(ip: str) -> float | None:
    """
    Ping a host once. Returns RTT in milliseconds, or None if no reply.
    Uses the system ping command to avoid needing raw socket privileges.
    Handles both Windows (-n) and Unix (-c) flags automatically.
    """
    flag = "-n" if os.name == "nt" else "-c"
    timeout_flag = ["-w", "800"] if os.name == "nt" else ["-W", "1"]
    try:
        r = subprocess.run(
            ["ping", flag, "1"] + timeout_flag + [ip],
            capture_output=True, text=True, timeout=3,
        )
        for line in r.stdout.splitlines():
            if "=" in line and "ms" in line.lower():
                for token in line.split():
                    if "ms" in token.lower() and "=" in token:
                        val = token.split("=")[-1].lower().replace("ms", "").strip()
                        try:
                            return float(val)
                        except ValueError:
                            pass
    except Exception:
        pass
    return None


def resolve_hostname(ip: str) -> str:
    """Reverse DNS lookup. Returns empty string if unresolvable."""
    try:
        name = socket.getfqdn(ip)
        return name if name != ip else ""
    except Exception:
        return ""


def probe_port(ip: str, port: int) -> bool:
    """
    Attempt a TCP connection to ip:port.
    Returns True if open (connection accepted), False otherwise.
    No data is sent — just the handshake.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TCP_TIMEOUT)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def grab_banner(ip: str, port: int) -> str:
    """
    Read the opening message from a service on a known-open port.
    Many protocols (SSH, FTP, SMTP, Redis, etc.) announce themselves
    immediately on connect. For HTTP we send a minimal HEAD request.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect((ip, port))
            if port in (80, 8080, 8008, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            raw = s.recv(256).decode("utf-8", errors="replace").strip()
            return raw.splitlines()[0][:100] if raw else ""
    except Exception:
        return ""


def get_service_name(port: int) -> str:
    """Human-readable name for a port number."""
    if port in PORT_NAMES:
        return PORT_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return ""


def scan_ports(ip: str) -> list[dict]:
    """
    Probe all COMMON_PORTS on one host in parallel, then grab banners
    from each open port. Returns a sorted list of open-port dicts.
    """
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=PORT_WORKERS) as ex:
        fs = {ex.submit(probe_port, ip, p): p for p in COMMON_PORTS}
        for f in concurrent.futures.as_completed(fs):
            p = fs[f]
            try:
                if f.result():
                    open_ports.append(p)
            except Exception:
                pass

    results = []
    for port in sorted(open_ports):
        results.append({
            "port":    port,
            "service": get_service_name(port),
            "banner":  grab_banner(ip, port),
        })
    return results


def guess_device_type(hostname: str, ports: list[dict]) -> str:
    """Heuristic device-type guess from open ports and hostname strings."""
    ps = {p["port"] for p in ports}
    h  = hostname.lower()

    if 3389 in ps:                    return "Windows PC / Server"
    if 5985 in ps or 5986 in ps:     return "Windows (WinRM)"
    if 32400 in ps:                   return "Plex Media Server"
    if 8096 in ps:                    return "Jellyfin Media Server"
    if {80, 443} <= ps and 22 in ps: return "Linux Web Server"
    if {80, 443} <= ps:               return "Web Server / Router / NAS"
    if 22 in ps and 445 not in ps:   return "Linux / Unix Server"
    if 445 in ps:                     return "Windows File Server"
    if 3306 in ps:                    return "MySQL Server"
    if 5432 in ps:                    return "PostgreSQL Server"
    if 27017 in ps:                   return "MongoDB Server"
    if 6379 in ps:                    return "Redis Server"
    if 5900 in ps:                    return "VNC Server"
    if 1883 in ps:                    return "IoT / MQTT Broker"
    if 9090 in ps or 9200 in ps:     return "Monitoring / Search"
    if any(x in h for x in ["router", "gateway", "modem", "fritz", "dsl"]):
        return "Router / Gateway"
    if any(x in h for x in ["tv", "chromecast", "roku", "fire", "appletv"]):
        return "Smart TV / Streaming"
    if any(x in h for x in ["phone", "android", "iphone", "ipad"]):
        return "Mobile Device"
    if any(x in h for x in ["printer", "hp", "canon", "epson", "brother"]):
        return "Printer"
    if any(x in h for x in ["cam", "camera", "nvr", "dvr"]):
        return "IP Camera / NVR"
    return "Unknown"


def scan_network(subnet: str):
    """
    Generator that scans the LAN and yields Server-Sent Events.

    Phase 1 — Parallel ping sweep to find live hosts.
    Phase 2 — Per-host port scan, banner grab, DNS, and type guess,
               running HOST_WORKERS hosts simultaneously.
    """

    # ── Phase 1: ping sweep ──────────────────────────────────────────────────
    yield _sse("status", {"msg": f"🔍 Pinging {subnet}…"})

    all_ips    = [str(ip) for ip in ipaddress.IPv4Network(subnet, strict=False).hosts()]
    live_hosts = []
    lock       = threading.Lock()

    def ping_collect(ip):
        ms = ping_host(ip)
        if ms is not None:
            with lock:
                live_hosts.append((ip, ms))

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(ping_collect, all_ips)

    live_hosts.sort(key=lambda x: ipaddress.IPv4Address(x[0]))

    yield _sse("status", {
        "msg": f"✅ {len(live_hosts)} host(s) alive — deep-scanning…"
    })

    if not live_hosts:
        yield _sse("done", {"msg": "No hosts responded to ping."})
        return

    # ── Phase 2: deep scan ───────────────────────────────────────────────────
    done = 0

    def deep_scan(item):
        ip, latency = item
        hostname = resolve_hostname(ip)
        ports    = scan_ports(ip)
        return {
            "ip":          ip,
            "hostname":    hostname,
            "latency_ms":  round(latency, 1),
            "open_ports":  ports,
            "device_type": guess_device_type(hostname, ports),
            "scanned_at":  datetime.now().strftime("%H:%M:%S"),
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=HOST_WORKERS) as ex:
        fs = {ex.submit(deep_scan, h): h for h in live_hosts}
        for f in concurrent.futures.as_completed(fs):
            ip, _ = fs[f]
            done += 1
            yield _sse("status", {"msg": f"🔬 Deep-scanning… ({done}/{len(live_hosts)} done)"})
            try:
                yield _sse("device", f.result())
            except Exception as e:
                yield _sse("error", {"msg": f"Error scanning {ip}: {e}"})

    yield _sse("done", {"msg": f"Complete — {len(live_hosts)} device(s) on {subnet}"})


def _sse(event: str, data) -> str:
    """Encode one Server-Sent Event frame."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ─────────────────────────────────────────────────────────────────────────────
# Flask web app
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetScope // Tailscale</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:      #070a0e;
    --surface: #0c1118;
    --border:  #1a2535;
    --accent:  #00e5ff;
    --accent2: #6c63ff;
    --green:   #00e676;
    --yellow:  #ffd740;
    --muted:   #37474f;
    --text:    #b0bec5;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--text);
    font-family: 'IBM Plex Mono', monospace; min-height: 100vh;
  }
  body::after {
    content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 9999;
    background: repeating-linear-gradient(0deg, transparent, transparent 3px,
      rgba(0,229,255,0.012) 3px, rgba(0,229,255,0.012) 4px);
  }
  header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 1.2rem 2rem; border-bottom: 1px solid var(--border);
    background: linear-gradient(135deg, #0c1118, #0d1520);
    position: sticky; top: 0; z-index: 100;
  }
  .wordmark {
    font-family: 'Syne', sans-serif; font-size: 1.3rem; font-weight: 800;
    color: #fff; letter-spacing: .03em;
  }
  .wordmark span { color: var(--accent); }
  .ts-pill {
    display: flex; align-items: center; gap: .45rem;
    font-size: .7rem; color: var(--muted); letter-spacing: .06em; text-transform: uppercase;
    border: 1px solid var(--border); padding: .25rem .65rem; border-radius: 999px;
  }
  .ts-dot {
    width: 6px; height: 6px; border-radius: 50%; background: var(--green);
    box-shadow: 0 0 6px var(--green); animation: blink 2.4s ease-in-out infinite;
  }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.25} }
  .hero {
    text-align: center; padding: 3.5rem 1.5rem 2rem;
    max-width: 640px; margin: 0 auto;
  }
  .hero h1 {
    font-family: 'Syne', sans-serif;
    font-size: clamp(2rem, 7vw, 3.8rem);
    font-weight: 800; line-height: 1.05; color: #fff; margin-bottom: 1rem;
  }
  .hero h1 em { font-style: normal; color: var(--accent); text-shadow: 0 0 40px rgba(0,229,255,.35); }
  .hero p { font-size: .82rem; line-height: 1.75; color: var(--muted); margin-bottom: 2rem; }
  #scanBtn {
    background: transparent; border: 1.5px solid var(--accent); color: var(--accent);
    font-family: 'IBM Plex Mono', monospace; font-size: .85rem;
    letter-spacing: .12em; text-transform: uppercase;
    padding: .8rem 2.4rem; cursor: pointer; border-radius: 3px;
    position: relative; overflow: hidden; transition: color .18s;
  }
  #scanBtn::before {
    content: ''; position: absolute; inset: 0; background: var(--accent);
    transform: scaleX(0); transform-origin: left; transition: transform .18s; z-index: -1;
  }
  #scanBtn:hover { color: var(--bg); }
  #scanBtn:hover::before { transform: scaleX(1); }
  #scanBtn:disabled { border-color: var(--muted); color: var(--muted); cursor: not-allowed; }
  #scanBtn:disabled::before { display: none; }
  #statusBar {
    text-align: center; font-size: .72rem; letter-spacing: .06em;
    color: var(--accent); min-height: 1.1em; margin: 1.4rem 0 .6rem;
  }
  .prog-track {
    max-width: 640px; margin: 0 auto 2rem;
    height: 2px; background: var(--border); border-radius: 1px; overflow: hidden;
  }
  #progBar {
    height: 100%; width: 0; border-radius: 1px;
    background: linear-gradient(90deg, var(--accent2), var(--accent));
    box-shadow: 0 0 8px var(--accent); transition: width .45s ease;
  }
  #results {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
    gap: 1.2rem; padding: 0 2rem 2rem; max-width: 1200px; margin: 0 auto;
  }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; overflow: hidden; animation: rise .4s ease both;
  }
  @keyframes rise { from{opacity:0;transform:translateY(14px)} to{opacity:1;transform:none} }
  .card-head {
    padding: 1rem 1.1rem .8rem;
    background: linear-gradient(90deg, rgba(108,99,255,.09), transparent);
    border-bottom: 1px solid var(--border);
  }
  .card-ip { font-family:'Syne',sans-serif; font-size:1.15rem; font-weight:700; color:#fff; margin-bottom:.15rem; }
  .card-hostname { font-size:.7rem; color:var(--accent); letter-spacing:.04em; }
  .card-tags { display:flex; flex-wrap:wrap; gap:.4rem; margin-top:.55rem; }
  .tag {
    font-size:.62rem; letter-spacing:.07em; text-transform:uppercase;
    padding:.18rem .5rem; border-radius:2px; border:1px solid;
  }
  .tag-type { color:var(--accent2); border-color:rgba(108,99,255,.35); background:rgba(108,99,255,.07); }
  .tag-lat  { color:var(--green);   border-color:rgba(0,230,118,.3);   background:rgba(0,230,118,.06); }
  .tag-cnt  { color:var(--yellow);  border-color:rgba(255,215,64,.3);  background:rgba(255,215,64,.06); }
  .card-body { padding:.85rem 1.1rem; }
  .section-label { font-size:.6rem; letter-spacing:.1em; text-transform:uppercase; color:var(--muted); margin-bottom:.5rem; }
  .port-tbl { width:100%; border-collapse:collapse; font-size:.73rem; }
  .port-tbl th {
    text-align:left; font-weight:400; font-size:.6rem; letter-spacing:.08em;
    text-transform:uppercase; color:var(--muted);
    padding:.22rem .4rem; border-bottom:1px solid var(--border);
  }
  .port-tbl td { padding:.28rem .4rem; border-bottom:1px solid rgba(26,37,53,.7); vertical-align:top; }
  .port-tbl tr:last-child td { border-bottom:none; }
  .p-num    { color:var(--accent2); font-weight:600; white-space:nowrap; }
  .p-svc    { color:var(--accent); }
  .p-banner { color:#607d8b; font-size:.65rem; word-break:break-all; }
  .no-ports { font-size:.72rem; color:var(--muted); font-style:italic; }
  #summary {
    display:none; margin:.5rem 2rem 3rem; max-width:1200px; margin-left:auto; margin-right:auto;
    padding:.9rem 1.2rem; background:var(--surface); border:1px solid var(--border);
    border-radius:6px; font-size:.75rem; color:var(--muted);
  }
  #summary strong { color:var(--accent); }
  @media(max-width:500px) { header{padding:1rem} #results{padding:0 1rem 2rem; grid-template-columns:1fr} }
</style>
</head>
<body>
<header>
  <div class="wordmark">Net<span>Scope</span></div>
  <div class="ts-pill"><div class="ts-dot"></div>Tailscale</div>
</header>
<div class="hero">
  <h1>Your Home Network,<br><em>Anywhere.</em></h1>
  <p>
    Scan your home network from anywhere in the world —
    delivered privately over Tailscale with no port forwarding,
    no firewall rules, and no configuration.
  </p>
  <button id="scanBtn" onclick="startScan()">⬡ Scan Network</button>
</div>
<div id="statusBar"></div>
<div class="prog-track"><div id="progBar"></div></div>
<div id="results"></div>
<div id="summary"></div>
<script>
let evtSrc=null, devCount=0, t0=null;

function startScan() {
  document.getElementById('scanBtn').disabled = true;
  document.getElementById('results').innerHTML = '';
  document.getElementById('summary').style.display = 'none';
  document.getElementById('progBar').style.width = '4%';
  devCount=0; t0=Date.now(); status('Initialising scan…');
  if (evtSrc) evtSrc.close();
  evtSrc = new EventSource('/scan');

  evtSrc.addEventListener('status', e => {
    const d = JSON.parse(e.data); status(d.msg);
    const b = document.getElementById('progBar');
    b.style.width = Math.min(parseFloat(b.style.width||4)+7, 88)+'%';
  });
  evtSrc.addEventListener('device', e => {
    devCount++; renderCard(JSON.parse(e.data));
    status(`Scanning… ${devCount} device(s) found so far`);
  });
  evtSrc.addEventListener('done', e => {
    const d = JSON.parse(e.data);
    document.getElementById('progBar').style.width = '100%';
    status('✓ ' + d.msg);
    document.getElementById('scanBtn').disabled = false;
    evtSrc.close();
    const s = document.getElementById('summary');
    s.style.display = 'block';
    s.innerHTML = `Completed in <strong>${((Date.now()-t0)/1000).toFixed(1)}s</strong> — `+
      `<strong>${devCount}</strong> device(s) found, `+
      `delivered privately over <strong>Tailscale</strong>.`;
  });
  evtSrc.addEventListener('error', e => {
    try { status('⚠ '+JSON.parse(e.data).msg); } catch(_){ status('Connection lost.'); }
  });
}

function status(msg) { document.getElementById('statusBar').textContent = msg; }

function renderCard(d) {
  const card = document.createElement('div');
  card.className = 'card';
  const portRows = (d.open_ports||[]).map(p =>
    `<tr>
      <td><span class="p-num">${esc(p.port)}</span></td>
      <td><span class="p-svc">${esc(p.service)}</span></td>
      <td>${p.banner?`<div class="p-banner">${esc(p.banner)}</div>`:''}</td>
    </tr>`
  ).join('');
  card.innerHTML = `
    <div class="card-head">
      <div class="card-ip">${esc(d.ip)}</div>
      ${d.hostname?`<div class="card-hostname">${esc(d.hostname)}</div>`:''}
      <div class="card-tags">
        ${d.device_type?`<span class="tag tag-type">${esc(d.device_type)}</span>`:''}
        ${d.latency_ms!=null?`<span class="tag tag-lat">${d.latency_ms} ms</span>`:''}
        ${d.open_ports?.length?`<span class="tag tag-cnt">${d.open_ports.length} open port${d.open_ports.length>1?'s':''}</span>`:''}
      </div>
    </div>
    <div class="card-body">
      ${portRows?`
        <div class="section-label">Open Ports &amp; Services</div>
        <table class="port-tbl">
          <thead><tr><th>Port</th><th>Service</th><th>Banner</th></tr></thead>
          <tbody>${portRows}</tbody>
        </table>`:`<span class="no-ports">No open ports found.</span>`}
      <div style="font-size:.6rem;color:var(--muted);margin-top:.6rem">scanned at ${esc(d.scanned_at)}</div>
    </div>`;
  document.getElementById('results').appendChild(card);
  card.scrollIntoView({behavior:'smooth',block:'nearest'});
}

function esc(s) {
  if (!s && s!==0) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
                  .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>"""


@app.route("/")
def index():
    return flask.Response(HTML, mimetype="text/html")


@app.route("/scan")
def scan():
    """
    SSE stream endpoint. Keeps the HTTP connection open and pushes JSON
    events as each device is discovered. The browser EventSource API
    handles this natively — no polling, no page reloads.
    """
    subnet = get_local_subnet()

    def generate():
        yield _sse("status", {"msg": f"Detected subnet: {subnet}"})
        yield from scan_network(subnet)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n  NetScope running on http://0.0.0.0:{PORT}")
    print(f"  If Tailscale is running, open http://<your-tailscale-ip>:{PORT}")
    print(  "  from any device on your tailnet.\n")
    print(  "  Press Ctrl+C to stop.\n")
    app.run(host="0.0.0.0", port=PORT, threaded=True)