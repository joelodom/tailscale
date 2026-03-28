#!/usr/bin/env python3
"""
tailscale.py  —  NetScope: Home Network Dashboard
==================================================

A thorough home network scanner accessible from any Tailscale device.

Key features:
  - Discovery via TCP connect to canary ports — finds devices that
    silently drop ICMP (phones, smart home gear, printers, etc.)
  - Scans ALL network interfaces, including Tailscale (100.x.x.x)
  - Port scan covers 1-10000 + a curated list of high ports
  - Live per-interface progress streamed to the browser as it happens

Requirements:
    pip install flask

Usage:
    python tailscale.py
"""

import concurrent.futures
import ipaddress
import json
import socket
import subprocess
import threading
from datetime import datetime

import flask
from flask import Flask, Response, stream_with_context

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

PORT = 5500

# Discovery: these ports are probed on every IP to decide if a host is alive.
# Chosen to cover the widest range of device types with minimal probes.
CANARY_PORTS = [
    80, 443, 22, 445, 3389, 8080, 8443, 23, 21,   # web, ssh, smb, rdp, ftp
    62078, 5353, 1900, 49152, 554, 7000, 8888,      # ios, mdns, upnp, bonjour, rtsp
    9100, 515, 631,                                  # printers
    1883, 8883, 5683,                                # iot / mqtt / coap
    3306, 5432, 6379, 27017,                         # databases
]

# Port scan range: 1-10000 covers the vast majority of real services.
SCAN_RANGE_END = 10000

# High ports added on top of the range scan.
EXTRA_HIGH_PORTS = [
    10050, 10051,           # Zabbix
    10250, 10255, 10256,    # Kubernetes kubelet
    11211,                  # Memcached
    15672, 15692,           # RabbitMQ management / prometheus
    16443,                  # MicroK8s API
    27017, 27018, 27019,    # MongoDB
    28015, 28016,           # RethinkDB
    32400,                  # Plex
    49152, 49153,           # Windows dynamic / Bonjour
    50000,                  # SAP
    51413,                  # BitTorrent
    54321,                  # CrateDB
    61208, 61209,           # Glances
    62078,                  # iPhone sync
]

ALL_PORTS = list(range(1, SCAN_RANGE_END + 1)) + [
    p for p in EXTRA_HIGH_PORTS if p > SCAN_RANGE_END
]

# Parallel workers
DISCOVERY_WORKERS = 300   # concurrent TCP probes during host discovery
PORT_SCAN_WORKERS = 500   # concurrent TCP probes during port scan per host

# TCP connect timeouts
DISCOVERY_TIMEOUT = 0.5
PORT_SCAN_TIMEOUT = 0.35

# Well-known port → friendly name
PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 79: "Finger",
    80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC/portmap",
    119: "NNTP", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DG", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    464: "Kerberos-chpw", 465: "SMTPS", 514: "Syslog/RSH",
    515: "LPD (Printer)", 520: "RIP", 554: "RTSP", 587: "SMTP-Submit",
    631: "IPP (Printer)", 636: "LDAPS", 873: "rsync",
    902: "VMware", 989: "FTPS-data", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS5",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle DB",
    1723: "PPTP", 1883: "MQTT", 1900: "UPnP/SSDP",
    2049: "NFS", 2181: "Zookeeper", 2375: "Docker",
    2376: "Docker-TLS", 2379: "etcd", 2380: "etcd-peer",
    3000: "Grafana/Dev", 3268: "LDAP-GC", 3306: "MySQL",
    3389: "RDP", 3478: "STUN/TURN", 4369: "Erlang-EPMD",
    4444: "Metasploit", 4500: "IKEv2", 4848: "GlassFish",
    5000: "UPnP/Dev", 5001: "Dev", 5353: "mDNS",
    5432: "PostgreSQL", 5601: "Kibana", 5672: "AMQP (RabbitMQ)",
    5683: "CoAP (IoT)", 5900: "VNC", 5984: "CouchDB",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
    6379: "Redis", 6443: "Kubernetes API",
    7000: "Cassandra/Dev", 7001: "WebLogic/Dev",
    7474: "Neo4j HTTP", 7687: "Neo4j Bolt",
    8009: "AJP", 8080: "HTTP-alt", 8086: "InfluxDB",
    8088: "InfluxDB-alt", 8096: "Jellyfin",
    8161: "ActiveMQ console", 8443: "HTTPS-alt",
    8554: "RTSP-alt", 8888: "Jupyter/HTTP",
    8920: "Jellyfin-HTTPS", 9000: "SonarQube/PHP-FPM",
    9090: "Prometheus", 9092: "Kafka", 9100: "Printer RAW",
    9200: "Elasticsearch HTTP", 9300: "Elasticsearch",
    9418: "Git", 10050: "Zabbix Agent",
    10250: "Kubelet", 11211: "Memcached",
    15672: "RabbitMQ Mgmt", 27017: "MongoDB",
    32400: "Plex", 49152: "Windows/Bonjour",
    51413: "BitTorrent", 61208: "Glances",
    62078: "iPhone sync",
}


# ─────────────────────────────────────────────────────────────────────────────
# Interface discovery
# ─────────────────────────────────────────────────────────────────────────────

def get_all_interfaces() -> list[dict]:
    """
    Enumerate all active IPv4 network interfaces on this machine,
    including the Tailscale interface (100.x.x.x).

    Returns a list of dicts:
      { "name": str, "ip": str, "subnet": str }

    Skips loopback (127.x) and link-local (169.254.x).
    For Tailscale's CGNAT range we scan only the local /24.
    """
    local_ips = []
    seen_subnets = set()

    # Primary hostname resolution
    try:
        hostname = socket.gethostname()
        all_addrs = socket.getaddrinfo(hostname, None, socket.AF_INET)
        local_ips.extend(addr[4][0] for addr in all_addrs)
    except Exception:
        pass

    # Outbound route trick for primary interface
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ips.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass

    # On Windows, ipconfig gives us all interface IPs reliably
    try:
        import re
        result = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=5
        )
        found = re.findall(r"IPv4 Address[^:]*:\s*([\d.]+)", result.stdout)
        local_ips.extend(found)
    except Exception:
        pass

    # On Linux/Mac, use ip addr or ifconfig
    try:
        import re
        for cmd in [["ip", "addr"], ["ifconfig", "-a"]]:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                found = re.findall(r"inet\s+([\d.]+)", result.stdout)
                local_ips.extend(found)
                break
    except Exception:
        pass

    # Deduplicate and classify
    interfaces = []
    for ip in dict.fromkeys(local_ips):   # preserve order, dedupe
        try:
            addr = ipaddress.IPv4Address(ip)
        except Exception:
            continue
        if addr.is_loopback or str(addr).startswith("169.254."):
            continue

        # Tailscale CGNAT range — scan /24 around our address only
        if addr in ipaddress.IPv4Network("100.64.0.0/10"):
            prefix = ip.rsplit(".", 1)[0]
            subnet_str = f"{prefix}.0/24"
            name = "Tailscale"
        else:
            prefix = ip.rsplit(".", 1)[0]
            subnet_str = f"{prefix}.0/24"
            name = f"LAN ({ip})"

        if subnet_str in seen_subnets:
            continue
        seen_subnets.add(subnet_str)

        interfaces.append({"name": name, "ip": ip, "subnet": subnet_str})

    return interfaces


# ─────────────────────────────────────────────────────────────────────────────
# TCP-based host discovery
# ─────────────────────────────────────────────────────────────────────────────

def tcp_probe(ip: str, port: int, timeout: float) -> bool:
    """Single TCP connect attempt. Returns True if the port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def discover_hosts(subnet: str, progress_cb=None) -> list[str]:
    """
    Find live hosts by TCP-connecting to CANARY_PORTS on every IP.
    A host is 'alive' if any canary port accepts a connection.

    This finds devices that silently drop ICMP — phones, IoT, many printers —
    as long as they have at least one listening TCP port.

    progress_cb(done, total) is called after each IP is finished.
    """
    net     = ipaddress.IPv4Network(subnet, strict=False)
    all_ips = [str(ip) for ip in net.hosts()]
    total   = len(all_ips)
    live    = []
    lock    = threading.Lock()
    done_n  = [0]

    def check_host(ip):
        found = any(tcp_probe(ip, p, DISCOVERY_TIMEOUT) for p in CANARY_PORTS)
        with lock:
            if found:
                live.append(ip)
            done_n[0] += 1
            if progress_cb:
                progress_cb(done_n[0], total)

    with concurrent.futures.ThreadPoolExecutor(max_workers=DISCOVERY_WORKERS) as ex:
        ex.map(check_host, all_ips)

    live.sort(key=lambda x: ipaddress.IPv4Address(x))
    return live


# ─────────────────────────────────────────────────────────────────────────────
# Port scanning
# ─────────────────────────────────────────────────────────────────────────────

def scan_ports(ip: str, progress_cb=None) -> list[dict]:
    """
    Probe ALL_PORTS (1-10000 + high ports) on a single host in parallel.
    For each open port, grab its banner.
    progress_cb(done, total) called as ports are checked.
    """
    total   = len(ALL_PORTS)
    done_n  = [0]
    opens   = []
    lock    = threading.Lock()

    def probe(port):
        is_open = tcp_probe(ip, port, PORT_SCAN_TIMEOUT)
        with lock:
            done_n[0] += 1
            if progress_cb:
                progress_cb(done_n[0], total)
            if is_open:
                opens.append(port)

    with concurrent.futures.ThreadPoolExecutor(max_workers=PORT_SCAN_WORKERS) as ex:
        ex.map(probe, ALL_PORTS)

    return [
        {"port": p, "service": get_service_name(p), "banner": grab_banner(ip, p)}
        for p in sorted(opens)
    ]


def grab_banner(ip: str, port: int) -> str:
    """Read the server's greeting on an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            s.connect((ip, port))
            if port in (80, 8080, 8008, 8888, 8000, 8081, 8082, 8090, 3000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            raw = s.recv(256).decode("utf-8", errors="replace").strip()
            return raw.splitlines()[0][:100] if raw else ""
    except Exception:
        return ""


def get_service_name(port: int) -> str:
    if port in PORT_NAMES:
        return PORT_NAMES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return ""


def resolve_hostname(ip: str) -> str:
    try:
        name = socket.getfqdn(ip)
        return name if name != ip else ""
    except Exception:
        return ""


def guess_device_type(hostname: str, ports: list[dict]) -> str:
    ps = {p["port"] for p in ports}
    h  = hostname.lower()
    if 3389 in ps:                         return "Windows PC / Server"
    if 5985 in ps or 5986 in ps:          return "Windows (WinRM)"
    if 32400 in ps:                        return "Plex Media Server"
    if 8096 in ps:                         return "Jellyfin Media Server"
    if {80, 443} <= ps and 22 in ps:      return "Linux Web Server"
    if {80, 443} <= ps:                    return "Web Server / Router / NAS"
    if 22 in ps and 445 not in ps:        return "Linux / Unix Server"
    if 445 in ps:                          return "Windows File Server"
    if 9100 in ps or 515 in ps or 631 in ps: return "Printer"
    if 62078 in ps:                        return "iPhone / iOS Device"
    if 3306 in ps:                         return "MySQL Server"
    if 5432 in ps:                         return "PostgreSQL Server"
    if 27017 in ps:                        return "MongoDB Server"
    if 6379 in ps:                         return "Redis Server"
    if 5900 in ps:                         return "VNC Server"
    if 1883 in ps:                         return "IoT / MQTT Broker"
    if 9090 in ps or 9200 in ps:          return "Monitoring / Search"
    if 9092 in ps:                         return "Kafka Broker"
    if any(x in h for x in ["router","gateway","modem","fritz","dsl"]):
        return "Router / Gateway"
    if any(x in h for x in ["tv","chromecast","roku","fire","appletv"]):
        return "Smart TV / Streaming"
    if any(x in h for x in ["phone","android","iphone","ipad"]):
        return "Mobile Device"
    if any(x in h for x in ["printer","hp","canon","epson","brother"]):
        return "Printer"
    if any(x in h for x in ["cam","camera","nvr","dvr"]):
        return "IP Camera / NVR"
    return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Main scan generator — yields SSE events
# ─────────────────────────────────────────────────────────────────────────────

def run_scan():
    """
    Scan all interfaces. Yields SSE event strings throughout.

    For each interface:
      1. Stream discovery progress (% of IPs TCP-probed) live
      2. Announce each host found during discovery
      3. Port-scan each host, streaming per-host progress
      4. Yield completed device record
    """
    interfaces = get_all_interfaces()

    if not interfaces:
        yield _sse("status", {"msg": "No network interfaces detected."})
        yield _sse("done",   {"msg": "No interfaces found."})
        return

    yield _sse("interfaces", {
        "interfaces": [{"name": i["name"], "subnet": i["subnet"]} for i in interfaces]
    })

    total_devices = 0

    for iface in interfaces:
        subnet = iface["subnet"]
        name   = iface["name"]

        yield _sse("iface_start", {"name": name, "subnet": subnet})
        yield _sse("status", {"msg": f"🔍 [{name}] Discovering hosts on {subnet}…"})

        # ── Discovery phase ──────────────────────────────────────────────────
        # Collect progress events in a list (can't yield from a callback thread)
        disc_events = []
        last_pct    = [-1]

        def disc_progress(done, total, name=name, subnet=subnet,
                          evts=disc_events, lp=last_pct):
            pct = int(done / total * 100)
            if pct != lp[0] and pct % 2 == 0:
                lp[0] = pct
                evts.append(_sse("discovery_progress", {
                    "name": name, "subnet": subnet,
                    "done": done, "total": total, "pct": pct,
                }))

        live_hosts = discover_hosts(subnet, progress_cb=disc_progress)

        for evt in disc_events:
            yield evt

        yield _sse("discovery_done", {
            "name": name, "subnet": subnet, "found": len(live_hosts),
        })
        yield _sse("status", {
            "msg": f"✅ [{name}] {len(live_hosts)} host(s) found — scanning ports…"
        })

        if not live_hosts:
            yield _sse("iface_done", {"name": name, "subnet": subnet, "devices": 0})
            continue

        # ── Port scan phase ──────────────────────────────────────────────────
        for ip in live_hosts:
            hostname = resolve_hostname(ip)
            short    = hostname.split(".")[0] if hostname else ip

            yield _sse("host_start", {"ip": ip, "name": name, "hostname": hostname})
            yield _sse("status", {
                "msg": f"🔬 [{name}] Scanning {ip} ({short}) — {len(ALL_PORTS)} ports…"
            })

            port_events = []
            last_pp     = [-1]

            def port_progress(done, total, ip=ip, name=name,
                              evts=port_events, lp=last_pp):
                pct = int(done / total * 100)
                if pct != lp[0] and pct % 5 == 0:
                    lp[0] = pct
                    evts.append(_sse("port_progress", {
                        "ip": ip, "name": name,
                        "done": done, "total": total, "pct": pct,
                    }))

            open_ports = scan_ports(ip, progress_cb=port_progress)

            for evt in port_events:
                yield evt

            total_devices += 1
            yield _sse("device", {
                "ip":          ip,
                "hostname":    hostname,
                "iface":       name,
                "subnet":      subnet,
                "open_ports":  open_ports,
                "device_type": guess_device_type(hostname, open_ports),
                "scanned_at":  datetime.now().strftime("%H:%M:%S"),
            })

        yield _sse("iface_done", {
            "name": name, "subnet": subnet, "devices": len(live_hosts)
        })

    yield _sse("done", {
        "msg": f"Scan complete — {total_devices} device(s) across {len(interfaces)} interface(s)"
    })


def _sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


# ─────────────────────────────────────────────────────────────────────────────
# Flask app
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
    --orange:  #ff9100;
    --muted:   #37474f;
    --text:    #b0bec5;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'IBM Plex Mono', monospace; min-height: 100vh; }
  body::after {
    content: ''; position: fixed; inset: 0; pointer-events: none; z-index: 9999;
    background: repeating-linear-gradient(0deg, transparent, transparent 3px,
      rgba(0,229,255,0.010) 3px, rgba(0,229,255,0.010) 4px);
  }

  header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 1.2rem 2rem; border-bottom: 1px solid var(--border);
    background: linear-gradient(135deg, #0c1118, #0d1520);
    position: sticky; top: 0; z-index: 100;
  }
  .wordmark { font-family:'Syne',sans-serif; font-size:1.3rem; font-weight:800; color:#fff; letter-spacing:.03em; }
  .wordmark span { color: var(--accent); }
  .ts-pill {
    display:flex; align-items:center; gap:.45rem; font-size:.7rem; color:var(--muted);
    letter-spacing:.06em; text-transform:uppercase;
    border:1px solid var(--border); padding:.25rem .65rem; border-radius:999px;
  }
  .ts-dot { width:6px; height:6px; border-radius:50%; background:var(--green); box-shadow:0 0 6px var(--green); animation:blink 2.4s ease-in-out infinite; }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.25} }

  .hero { text-align:center; padding:2.5rem 1.5rem 1.5rem; max-width:640px; margin:0 auto; }
  .hero h1 { font-family:'Syne',sans-serif; font-size:clamp(1.8rem,6vw,3.2rem); font-weight:800; line-height:1.05; color:#fff; margin-bottom:.8rem; }
  .hero h1 em { font-style:normal; color:var(--accent); text-shadow:0 0 40px rgba(0,229,255,.35); }
  .hero p { font-size:.8rem; line-height:1.75; color:var(--muted); margin-bottom:1.5rem; }

  #scanBtn {
    background:transparent; border:1.5px solid var(--accent); color:var(--accent);
    font-family:'IBM Plex Mono',monospace; font-size:.85rem; letter-spacing:.12em; text-transform:uppercase;
    padding:.75rem 2.2rem; cursor:pointer; border-radius:3px; position:relative; overflow:hidden; transition:color .18s;
  }
  #scanBtn::before { content:''; position:absolute; inset:0; background:var(--accent); transform:scaleX(0); transform-origin:left; transition:transform .18s; z-index:-1; }
  #scanBtn:hover { color:var(--bg); }
  #scanBtn:hover::before { transform:scaleX(1); }
  #scanBtn:disabled { border-color:var(--muted); color:var(--muted); cursor:not-allowed; }
  #scanBtn:disabled::before { display:none; }

  #statusBar { text-align:center; font-size:.72rem; letter-spacing:.06em; color:var(--accent); min-height:1.1em; margin:1.2rem 0 .5rem; padding:0 1rem; }

  /* Interface panels */
  #ifacePanels { max-width:1200px; margin:0 auto; padding:0 2rem 1rem; display:flex; flex-direction:column; gap:.75rem; }
  .iface-panel { background:var(--surface); border:1px solid var(--border); border-radius:6px; overflow:hidden; }
  .iface-header {
    display:grid; grid-template-columns:1fr auto auto; align-items:center; gap:1rem;
    padding:.6rem 1rem; border-bottom:1px solid var(--border);
    background:linear-gradient(90deg, rgba(0,229,255,.05), transparent);
  }
  .iface-name { font-size:.75rem; font-weight:600; color:var(--accent); letter-spacing:.06em; text-transform:uppercase; }
  .iface-subnet { font-size:.65rem; color:var(--muted); }
  .iface-stats  { font-size:.65rem; color:var(--muted); text-align:right; }
  .disc-track { height:3px; background:rgba(255,255,255,.04); }
  .disc-bar   { height:100%; width:0; background:linear-gradient(90deg,var(--accent2),var(--accent)); transition:width .3s ease; }
  .iface-hosts { padding:.3rem 0; }

  /* Host rows */
  .host-row {
    display:grid; grid-template-columns:140px 1fr auto;
    align-items:center; gap:.6rem; padding:.32rem 1rem;
    border-bottom:1px solid rgba(26,37,53,.5); font-size:.7rem;
    transition: background .15s;
  }
  .host-row:last-child { border-bottom:none; }
  .host-row.done { background: rgba(0,230,118,.03); }
  .host-ip  { color:#fff; font-weight:600; font-family:'Syne',sans-serif; font-size:.78rem; }
  .host-name { color:var(--muted); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:.65rem; }
  .host-prog { display:flex; align-items:center; gap:.4rem; white-space:nowrap; }
  .mini-track { width:90px; height:2px; background:rgba(255,255,255,.07); border-radius:1px; overflow:hidden; }
  .mini-bar   { height:100%; width:0; background:var(--accent2); transition:width .2s ease; border-radius:1px; }
  .host-pct   { font-size:.6rem; color:var(--muted); min-width:2.8em; text-align:right; }

  /* Device cards */
  #results {
    display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr));
    gap:1.2rem; padding:.5rem 2rem 2rem; max-width:1200px; margin:0 auto;
  }
  .card { background:var(--surface); border:1px solid var(--border); border-radius:6px; overflow:hidden; animation:rise .4s ease both; }
  @keyframes rise { from{opacity:0;transform:translateY(14px)} to{opacity:1;transform:none} }
  .card-head {
    padding:1rem 1.1rem .8rem;
    background:linear-gradient(90deg,rgba(108,99,255,.09),transparent);
    border-bottom:1px solid var(--border);
  }
  .card-ip { font-family:'Syne',sans-serif; font-size:1.1rem; font-weight:700; color:#fff; margin-bottom:.15rem; }
  .card-hostname { font-size:.7rem; color:var(--accent); letter-spacing:.04em; }
  .card-tags { display:flex; flex-wrap:wrap; gap:.4rem; margin-top:.55rem; }
  .tag { font-size:.62rem; letter-spacing:.07em; text-transform:uppercase; padding:.18rem .5rem; border-radius:2px; border:1px solid; }
  .tag-type  { color:var(--accent2); border-color:rgba(108,99,255,.35); background:rgba(108,99,255,.07); }
  .tag-iface { color:var(--orange);  border-color:rgba(255,145,0,.3);   background:rgba(255,145,0,.06); }
  .tag-cnt   { color:var(--yellow);  border-color:rgba(255,215,64,.3);  background:rgba(255,215,64,.06); }
  .tag-ts    { color:#5bc0eb;        border-color:rgba(91,192,235,.3);  background:rgba(91,192,235,.06); }
  .card-body { padding:.85rem 1.1rem; }
  .section-label { font-size:.6rem; letter-spacing:.1em; text-transform:uppercase; color:var(--muted); margin-bottom:.5rem; }
  .port-tbl { width:100%; border-collapse:collapse; font-size:.73rem; }
  .port-tbl th { text-align:left; font-weight:400; font-size:.6rem; letter-spacing:.08em; text-transform:uppercase; color:var(--muted); padding:.22rem .4rem; border-bottom:1px solid var(--border); }
  .port-tbl td { padding:.28rem .4rem; border-bottom:1px solid rgba(26,37,53,.7); vertical-align:top; }
  .port-tbl tr:last-child td { border-bottom:none; }
  .p-num    { color:var(--accent2); font-weight:600; white-space:nowrap; }
  .p-svc    { color:var(--accent); }
  .p-banner { color:#607d8b; font-size:.65rem; word-break:break-all; }
  .no-ports { font-size:.72rem; color:var(--muted); font-style:italic; }

  #summary {
    display:none; margin:.5rem 2rem 3rem; max-width:1200px; margin-left:auto; margin-right:auto;
    padding:.9rem 1.2rem; background:var(--surface); border:1px solid var(--border); border-radius:6px;
    font-size:.75rem; color:var(--muted);
  }
  #summary strong { color:var(--accent); }

  @media(max-width:520px) {
    header { padding:1rem; }
    #ifacePanels, #results { padding-left:1rem; padding-right:1rem; }
    #results { grid-template-columns:1fr; }
    .host-row { grid-template-columns:110px 1fr; }
    .host-prog { display:none; }
  }
</style>
</head>
<body>

<header>
  <div class="wordmark">Net<span>Scope</span></div>
  <div class="ts-pill"><div class="ts-dot"></div>Tailscale</div>
</header>

<div class="hero">
  <h1>Your Home Network,<br><em>Anywhere.</em></h1>
  <p>TCP-based discovery across every interface — finds devices that<br>
  ignore ping. Ports 1–10 000 + high ports scanned per host.</p>
  <button id="scanBtn" onclick="startScan()">⬡ Scan Network</button>
</div>

<div id="statusBar"></div>
<div id="ifacePanels"></div>
<div id="results"></div>
<div id="summary"></div>

<script>
let evtSrc = null, devCount = 0, t0 = null;
const ifaces = {};  // name → { discBar, hostsDiv, statsEl }
const hostEls = {}; // ip   → { row, miniBar, pctEl }
// ip → interface name, so port_progress can find the right panel
const ipToIface = {};

function startScan() {
  document.getElementById('scanBtn').disabled = true;
  document.getElementById('ifacePanels').innerHTML = '';
  document.getElementById('results').innerHTML = '';
  document.getElementById('summary').style.display = 'none';
  devCount = 0; t0 = Date.now();
  for (const k in ifaces)  delete ifaces[k];
  for (const k in hostEls) delete hostEls[k];
  for (const k in ipToIface) delete ipToIface[k];
  setStatus('Detecting interfaces…');

  if (evtSrc) evtSrc.close();
  evtSrc = new EventSource('/scan');

  evtSrc.addEventListener('interfaces', e => {
    JSON.parse(e.data).interfaces.forEach(i => buildPanel(i.name, i.subnet));
  });

  evtSrc.addEventListener('discovery_progress', e => {
    const d = JSON.parse(e.data);
    const panel = ifaces[d.name];
    if (!panel) return;
    panel.discBar.style.width = d.pct + '%';
    panel.statsEl.textContent = `Checking IPs… ${d.pct}%`;
  });

  evtSrc.addEventListener('discovery_done', e => {
    const d = JSON.parse(e.data);
    const panel = ifaces[d.name];
    if (!panel) return;
    panel.discBar.style.width = '100%';
    panel.discBar.style.background = 'var(--green)';
    panel.statsEl.textContent = `${d.found} host${d.found !== 1 ? 's' : ''} found`;
  });

  evtSrc.addEventListener('host_start', e => {
    const d = JSON.parse(e.data);
    ipToIface[d.ip] = d.name;
    addHostRow(d.ip, d.name, d.hostname);
  });

  evtSrc.addEventListener('port_progress', e => {
    const d = JSON.parse(e.data);
    const h = hostEls[d.ip];
    if (!h) return;
    h.miniBar.style.width = d.pct + '%';
    h.pctEl.textContent   = d.pct + '%';
  });

  evtSrc.addEventListener('device', e => {
    devCount++;
    const d = JSON.parse(e.data);
    finishHost(d.ip, d.open_ports?.length ?? 0);
    renderCard(d);
    setStatus(`${devCount} device(s) complete — scanning continues…`);
  });

  evtSrc.addEventListener('status', e => {
    setStatus(JSON.parse(e.data).msg);
  });

  evtSrc.addEventListener('iface_done', e => {
    const d = JSON.parse(e.data);
    const panel = ifaces[d.name];
    if (panel) panel.statsEl.textContent = `✓ ${d.devices} device${d.devices !== 1 ? 's' : ''}`;
  });

  evtSrc.addEventListener('done', e => {
    setStatus('✓ ' + JSON.parse(e.data).msg);
    document.getElementById('scanBtn').disabled = false;
    evtSrc.close();
    const s = document.getElementById('summary');
    s.style.display = 'block';
    s.innerHTML = `Completed in <strong>${((Date.now()-t0)/1000).toFixed(1)}s</strong> — `+
      `<strong>${devCount}</strong> device(s) found, delivered privately over <strong>Tailscale</strong>.`;
  });

  evtSrc.addEventListener('error', e => {
    try { setStatus('⚠ ' + JSON.parse(e.data).msg); } catch(_) { setStatus('Connection lost.'); }
  });
}

function setStatus(msg) { document.getElementById('statusBar').textContent = msg; }

function buildPanel(name, subnet) {
  const isTailscale = name.toLowerCase().includes('tailscale');
  const panel = document.createElement('div');
  panel.className = 'iface-panel';
  const safeId = name.replace(/[^a-zA-Z0-9]/g, '-');
  panel.innerHTML = `
    <div class="iface-header">
      <div>
        <span class="iface-name">${esc(name)}</span>
        ${isTailscale ? ' <span class="tag tag-ts" style="vertical-align:middle;margin-left:.4rem">tailnet</span>' : ''}
      </div>
      <span class="iface-subnet">${esc(subnet)}</span>
      <span class="iface-stats" id="stats-${safeId}">Starting…</span>
    </div>
    <div class="disc-track"><div class="disc-bar" id="disc-${safeId}"></div></div>
    <div class="iface-hosts" id="hosts-${safeId}"></div>`;
  document.getElementById('ifacePanels').appendChild(panel);
  ifaces[name] = {
    discBar:  panel.querySelector('.disc-bar'),
    hostsDiv: panel.querySelector('.iface-hosts'),
    statsEl:  panel.querySelector('.iface-stats'),
  };
}

function addHostRow(ip, ifaceName, hostname) {
  const panel = ifaces[ifaceName];
  if (!panel || hostEls[ip]) return;
  const safeIp = ip.replace(/\./g, '-');
  const row = document.createElement('div');
  row.className = 'host-row';
  row.innerHTML = `
    <span class="host-ip">${esc(ip)}</span>
    <span class="host-name">${esc(hostname || 'resolving…')}</span>
    <div class="host-prog">
      <div class="mini-track"><div class="mini-bar" id="mini-${safeIp}"></div></div>
      <span class="host-pct" id="pct-${safeIp}">0%</span>
    </div>`;
  panel.hostsDiv.appendChild(row);
  hostEls[ip] = {
    row,
    miniBar: row.querySelector('.mini-bar'),
    pctEl:   row.querySelector('.host-pct'),
  };
}

function finishHost(ip, portCount) {
  const h = hostEls[ip];
  if (!h) return;
  h.miniBar.style.width = '100%';
  h.miniBar.style.background = 'var(--green)';
  h.pctEl.textContent = portCount > 0 ? `${portCount}p` : '✓';
  h.pctEl.style.color = portCount > 0 ? 'var(--yellow)' : 'var(--green)';
  h.row.classList.add('done');
}

function renderCard(d) {
  const card = document.createElement('div');
  card.className = 'card';
  const isTailscale = d.iface?.toLowerCase().includes('tailscale');
  const portRows = (d.open_ports || []).map(p =>
    `<tr>
      <td><span class="p-num">${esc(p.port)}</span></td>
      <td><span class="p-svc">${esc(p.service)}</span></td>
      <td>${p.banner ? `<div class="p-banner">${esc(p.banner)}</div>` : ''}</td>
    </tr>`
  ).join('');
  card.innerHTML = `
    <div class="card-head">
      <div class="card-ip">${esc(d.ip)}</div>
      ${d.hostname ? `<div class="card-hostname">${esc(d.hostname)}</div>` : ''}
      <div class="card-tags">
        ${d.device_type ? `<span class="tag tag-type">${esc(d.device_type)}</span>` : ''}
        ${isTailscale   ? `<span class="tag tag-ts">tailnet</span>` : (d.iface ? `<span class="tag tag-iface">${esc(d.iface)}</span>` : '')}
        ${d.open_ports?.length ? `<span class="tag tag-cnt">${d.open_ports.length} port${d.open_ports.length > 1 ? 's' : ''}</span>` : ''}
      </div>
    </div>
    <div class="card-body">
      ${portRows ? `
        <div class="section-label">Open Ports &amp; Services</div>
        <table class="port-tbl">
          <thead><tr><th>Port</th><th>Service</th><th>Banner</th></tr></thead>
          <tbody>${portRows}</tbody>
        </table>` : `<span class="no-ports">No open ports found.</span>`}
      <div style="font-size:.6rem;color:var(--muted);margin-top:.6rem">scanned at ${esc(d.scanned_at)}</div>
    </div>`;
  document.getElementById('results').appendChild(card);
  card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function esc(s) {
  if (!s && s !== 0) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>
</body>
</html>"""


@app.route("/")
def index():
    return flask.Response(HTML, mimetype="text/html")


@app.route("/scan")
def scan():
    return Response(
        stream_with_context(run_scan()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


if __name__ == "__main__":
    total_ports = len(ALL_PORTS)
    print(f"\n  NetScope — TCP scanner, ports 1–{SCAN_RANGE_END} + high ports ({total_ports} total per host)")
    print(f"  Running on http://0.0.0.0:{PORT}")
    print(f"  Open http://<your-tailscale-ip>:{PORT} from any tailnet device.\n")
    print(  "  Press Ctrl+C to stop.\n")
    app.run(host="0.0.0.0", port=PORT, threaded=True)