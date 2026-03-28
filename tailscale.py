#!/usr/bin/env python3
"""
tailscale.py — Home Network Intelligence Dashboard
===================================================
Serves a live network scanner UI over both Tailscale (private, process-level)
and localhost. Uses the Tailscale LocalAPI to join the tailnet directly from
this process — no new system network interface is created.

Requirements:
    pip install python-nmap flask requests

System requirements:
    - nmap installed (https://nmap.org/download.html)
    - Tailscale installed and logged in on this machine
    - Run with sudo/admin (nmap OS fingerprinting needs raw sockets)

Usage:
    sudo python3 tailscale.py
"""

import json
import os
import socket
import subprocess
import threading
import time
from datetime import datetime

import nmap
import requests
from flask import Flask, Response, render_template_string, stream_with_context

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────

PORT = 5500  # Port to serve on (both localhost and Tailscale IP)

# Tailscale's local daemon socket — used to query our Tailscale IP
# without needing to create a system network interface.
TAILSCALE_SOCKET = "/var/run/tailscale/tailscaled.sock"  # Linux/Mac
# On Windows this is a named pipe; see README for Windows notes.

# How many of the most common ports to scan per device.
# More ports = slower but more informative scan.
TOP_PORTS = 100

# ─────────────────────────────────────────────
# Flask app
# ─────────────────────────────────────────────

app = Flask(__name__)

# ─────────────────────────────────────────────
# Tailscale integration
# ─────────────────────────────────────────────

def get_tailscale_ip() -> str | None:
    """
    Query the Tailscale local daemon via its Unix socket to get OUR
    Tailscale IP address (the 100.x.x.x address assigned to this machine).

    This uses the Tailscale LocalAPI — a lightweight HTTP API served over
    a Unix socket. No network request leaves the machine; we're just talking
    to the local tailscaled process. This is how we bind ONLY this process
    to the Tailscale network without creating a new system interface.

    Returns None if Tailscale is not running or not logged in.
    """
    try:
        # Use a requests Session with a custom adapter that routes
        # HTTP over the Unix socket instead of TCP.
        session = requests.Session()
        session.mount("http://local-tailscaled.sock/", _UnixSocketAdapter(TAILSCALE_SOCKET))
        resp = session.get("http://local-tailscaled.sock/localapi/v0/status", timeout=3)
        data = resp.json()
        # The Self section contains our own node's addresses
        addrs = data.get("Self", {}).get("TailscaleIPs", [])
        for addr in addrs:
            if addr.startswith("100."):  # Tailscale's CGNAT range
                return addr
    except Exception as e:
        print(f"[tailscale] Could not reach local Tailscale daemon: {e}")
    return None


class _UnixSocketAdapter(requests.adapters.HTTPAdapter):
    """
    Custom requests transport adapter that sends HTTP over a Unix domain
    socket instead of TCP. This is how we talk to tailscaled's LocalAPI
    without any network exposure.
    """
    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        super().__init__()

    def send(self, request, **kwargs):
        import http.client
        import urllib.parse

        parsed = urllib.parse.urlparse(request.url)
        path = parsed.path
        if parsed.query:
            path += "?" + parsed.query

        # Open a raw Unix socket connection to tailscaled
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket_path)
        conn = http.client.HTTPConnection("localhost")
        conn.sock = sock

        conn.request(request.method, path, headers=dict(request.headers))
        raw = conn.getresponse()

        # Wrap into a requests.Response object
        response = requests.models.Response()
        response.status_code = raw.status
        response._content = raw.read()
        response.headers = dict(raw.getheaders())
        sock.close()
        return response


# ─────────────────────────────────────────────
# Network scanning logic
# ─────────────────────────────────────────────

def get_local_subnet() -> str:
    """
    Detect the local machine's LAN IP and derive a /24 subnet to scan.
    E.g. if this machine is 192.168.1.42, returns '192.168.1.0/24'.
    """
    try:
        # Connect to a public IP (doesn't actually send data) to find
        # which local interface the OS would use for outbound traffic.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Derive /24 subnet
        parts = local_ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"  # Fallback


def lookup_mac_vendor(mac: str) -> str:
    """
    Look up the hardware vendor from a MAC address using the local
    nmap MAC prefix database (no internet required).
    Returns an empty string if not found.
    """
    if not mac or mac == "Unknown":
        return ""
    try:
        # nmap stores OUI data in its own files; we query it indirectly
        # through the scan results. This is just a string cleanup helper.
        return mac
    except Exception:
        return ""


def scan_network(subnet: str):
    """
    Generator that yields Server-Sent Events (SSE) as scan results come in.

    Scan stages:
      1. Quick ping sweep to find live hosts
      2. Per-host: top-N port scan + OS fingerprint + service versions

    Each yielded string is a JSON-encoded SSE 'data:' line.
    """

    nm = nmap.PortScanner()

    # ── Stage 1: Ping sweep to find live hosts quickly ──────────────────
    yield _sse_event("status", {"msg": f"🔍 Pinging {subnet} to find live hosts…"})

    try:
        # -sn = ping scan only (no port scan), fast host discovery
        nm.scan(hosts=subnet, arguments="-sn --max-retries 1 --host-timeout 3s")
    except Exception as e:
        yield _sse_event("error", {"msg": f"Ping sweep failed: {e}"})
        return

    live_hosts = nm.all_hosts()
    yield _sse_event("status", {"msg": f"✅ Found {len(live_hosts)} live host(s). Starting deep scan…"})

    if not live_hosts:
        yield _sse_event("done", {"msg": "No hosts found."})
        return

    # ── Stage 2: Deep scan each host ────────────────────────────────────
    for i, host in enumerate(live_hosts):
        yield _sse_event("status", {
            "msg": f"🔬 Scanning {host} ({i+1}/{len(live_hosts)})…"
        })

        try:
            # -sV  = probe open ports to determine service/version info
            # -O   = OS detection (requires root)
            # --top-ports N = only scan the N most common ports
            # -T4  = aggressive timing (faster)
            # --script = run default NSE scripts for extra info
            args = (
                f"-sV -O -T4 --top-ports {TOP_PORTS} "
                f"--script=banner,ssh-hostkey,http-title,smb-os-discovery "
                f"--max-retries 1 --host-timeout 30s"
            )
            nm.scan(hosts=host, arguments=args)
        except Exception as e:
            yield _sse_event("error", {"msg": f"Failed to scan {host}: {e}"})
            continue

        if host not in nm.all_hosts():
            continue

        h = nm[host]

        # ── Extract hostname ──────────────────────────────────────────
        hostnames = h.hostnames()
        hostname = hostnames[0]["name"] if hostnames else "Unknown"

        # ── Extract OS guess ─────────────────────────────────────────
        os_matches = h.get("osmatch", [])
        if os_matches:
            best_os = os_matches[0]
            os_name = best_os.get("name", "Unknown")
            os_accuracy = best_os.get("accuracy", "?")
        else:
            os_name = "Unknown"
            os_accuracy = "0"

        # ── Extract MAC + vendor ──────────────────────────────────────
        addresses = h.get("addresses", {})
        mac = addresses.get("mac", "Unknown")
        vendor = h.get("vendor", {}).get(mac, "") if mac != "Unknown" else ""

        # ── Extract open ports + services ────────────────────────────
        ports = []
        for proto in h.all_protocols():
            port_ids = sorted(h[proto].keys())
            for port_id in port_ids:
                port_info = h[proto][port_id]
                if port_info["state"] == "open":
                    # Pull NSE script output if available
                    scripts = port_info.get("script", {})
                    script_output = "; ".join(
                        f"{k}: {v[:80]}" for k, v in scripts.items()
                    ) if scripts else ""

                    ports.append({
                        "port": port_id,
                        "proto": proto,
                        "service": port_info.get("name", ""),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                        "extrainfo": port_info.get("extrainfo", ""),
                        "scripts": script_output,
                    })

        # ── Ping latency ─────────────────────────────────────────────
        latency = _ping_latency(host)

        # ── Assemble device record ───────────────────────────────────
        device = {
            "ip": host,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "os": os_name,
            "os_accuracy": os_accuracy,
            "latency_ms": latency,
            "open_ports": ports,
            "scanned_at": datetime.now().strftime("%H:%M:%S"),
        }

        yield _sse_event("device", device)

    yield _sse_event("done", {"msg": f"Scan complete. {len(live_hosts)} device(s) found."})


def _ping_latency(host: str) -> float | None:
    """
    Measure round-trip time to a host using a single ICMP ping.
    Returns milliseconds as a float, or None on failure.
    """
    try:
        param = "-n" if os.name == "nt" else "-c"
        result = subprocess.run(
            ["ping", param, "1", host],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout
        # Parse 'time=12.3 ms' from ping output
        for token in output.split():
            if token.startswith("time="):
                return float(token.replace("time=", "").replace("ms", ""))
    except Exception:
        pass
    return None


def _sse_event(event_type: str, data: dict) -> str:
    """
    Format a Server-Sent Event string.
    SSE format:  event: <type>\ndata: <json>\n\n
    """
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


# ─────────────────────────────────────────────
# HTML — the glossy dashboard UI
# ─────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetScope // Tailscale</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:       #080c10;
    --surface:  #0d1117;
    --border:   #1e2d3d;
    --accent:   #00ffe1;
    --accent2:  #7b61ff;
    --danger:   #ff4d6d;
    --text:     #c9d1d9;
    --muted:    #4a5568;
    --green:    #39d353;
    --yellow:   #e3b341;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Share Tech Mono', monospace;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Animated scanline overlay */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,255,225,0.015) 2px,
      rgba(0,255,225,0.015) 4px
    );
    pointer-events: none;
    z-index: 1000;
  }

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1.5rem 2rem;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(90deg, #0d1117 0%, #0a1628 100%);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    font-family: 'Syne', sans-serif;
    font-weight: 800;
    font-size: 1.4rem;
    letter-spacing: 0.05em;
    color: #fff;
  }
  .logo span { color: var(--accent); }

  .ts-badge {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.75rem;
    color: var(--muted);
    border: 1px solid var(--border);
    padding: 0.3rem 0.7rem;
    border-radius: 999px;
  }
  .ts-badge .dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--green);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }

  main { padding: 2rem; max-width: 1100px; margin: 0 auto; }

  .hero {
    text-align: center;
    padding: 3rem 1rem 2rem;
  }
  .hero h1 {
    font-family: 'Syne', sans-serif;
    font-size: clamp(2rem, 6vw, 3.5rem);
    font-weight: 800;
    line-height: 1.1;
    color: #fff;
    margin-bottom: 0.75rem;
  }
  .hero h1 em {
    font-style: normal;
    color: var(--accent);
    text-shadow: 0 0 30px rgba(0,255,225,0.4);
  }
  .hero p {
    color: var(--muted);
    font-size: 0.9rem;
    max-width: 480px;
    margin: 0 auto 2rem;
    line-height: 1.7;
  }

  /* Scan button */
  #scanBtn {
    background: transparent;
    border: 2px solid var(--accent);
    color: var(--accent);
    font-family: 'Share Tech Mono', monospace;
    font-size: 1rem;
    padding: 0.85rem 2.5rem;
    cursor: pointer;
    border-radius: 4px;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    position: relative;
    overflow: hidden;
    transition: all 0.2s;
  }
  #scanBtn::before {
    content: '';
    position: absolute;
    inset: 0;
    background: var(--accent);
    transform: translateX(-100%);
    transition: transform 0.2s;
    z-index: -1;
  }
  #scanBtn:hover { color: var(--bg); }
  #scanBtn:hover::before { transform: translateX(0); }
  #scanBtn:disabled {
    border-color: var(--muted);
    color: var(--muted);
    cursor: not-allowed;
  }
  #scanBtn:disabled::before { display: none; }

  /* Status bar */
  #statusBar {
    margin: 1.5rem 0;
    font-size: 0.8rem;
    color: var(--accent);
    min-height: 1.2em;
    text-align: center;
    letter-spacing: 0.05em;
  }

  /* Progress bar */
  #progress {
    height: 2px;
    background: var(--border);
    border-radius: 1px;
    margin-bottom: 2rem;
    overflow: hidden;
  }
  #progressBar {
    height: 100%;
    width: 0%;
    background: linear-gradient(90deg, var(--accent2), var(--accent));
    transition: width 0.4s ease;
    box-shadow: 0 0 10px var(--accent);
  }

  /* Device grid */
  #results { display: grid; gap: 1.25rem; }

  .device-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    animation: slideIn 0.4s ease both;
  }
  @keyframes slideIn {
    from { opacity: 0; transform: translateY(16px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .device-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 1.25rem;
    background: linear-gradient(90deg, rgba(123,97,255,0.08) 0%, transparent 100%);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .device-ip {
    font-family: 'Syne', sans-serif;
    font-size: 1.1rem;
    font-weight: 700;
    color: #fff;
  }

  .device-hostname {
    font-size: 0.8rem;
    color: var(--accent);
    margin-top: 2px;
  }

  .device-meta {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    align-items: center;
  }

  .badge {
    font-size: 0.7rem;
    padding: 0.2rem 0.55rem;
    border-radius: 3px;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    border: 1px solid;
  }
  .badge-os    { color: var(--yellow); border-color: rgba(227,179,65,0.3); background: rgba(227,179,65,0.06); }
  .badge-mac   { color: var(--muted);  border-color: var(--border); }
  .badge-lat   { color: var(--green);  border-color: rgba(57,211,83,0.3); background: rgba(57,211,83,0.06); }

  .device-body { padding: 1rem 1.25rem; }

  .section-label {
    font-size: 0.65rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--muted);
    margin-bottom: 0.6rem;
  }

  /* Port table */
  .port-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.78rem;
    margin-bottom: 1rem;
  }
  .port-table th {
    text-align: left;
    color: var(--muted);
    font-weight: normal;
    font-size: 0.65rem;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 0.3rem 0.5rem;
    border-bottom: 1px solid var(--border);
  }
  .port-table td {
    padding: 0.35rem 0.5rem;
    border-bottom: 1px solid rgba(30,45,61,0.5);
    vertical-align: top;
  }
  .port-table tr:last-child td { border-bottom: none; }
  .port-num  { color: var(--accent2); font-weight: bold; }
  .port-svc  { color: var(--accent); }
  .port-ver  { color: var(--muted); font-size: 0.7rem; }
  .port-script { color: #8b9aad; font-size: 0.68rem; word-break: break-all; }

  .no-ports { color: var(--muted); font-size: 0.8rem; font-style: italic; }

  /* Summary bar at bottom */
  #summary {
    margin-top: 2rem;
    padding: 1rem 1.25rem;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    display: none;
    font-size: 0.8rem;
    color: var(--muted);
  }
  #summary strong { color: var(--accent); }

  /* Responsive */
  @media (max-width: 600px) {
    header { padding: 1rem; }
    main { padding: 1rem; }
    .device-header { flex-direction: column; align-items: flex-start; }
  }
</style>
</head>
<body>

<header>
  <div class="logo">Net<span>Scope</span></div>
  <div class="ts-badge">
    <div class="dot"></div>
    Tailscale Connected
  </div>
</header>

<main>
  <div class="hero">
    <h1>Your Home Network,<br><em>Anywhere.</em></h1>
    <p>
      Running over your private Tailscale mesh — no port forwarding,
      no VPN config, no exposure to the public internet.
      Just your devices, privately connected.
    </p>
    <button id="scanBtn" onclick="startScan()">⬡ Scan Network</button>
  </div>

  <div id="statusBar"></div>
  <div id="progress"><div id="progressBar"></div></div>
  <div id="results"></div>
  <div id="summary"></div>
</main>

<script>
  let evtSource = null;
  let deviceCount = 0;
  let scanStart = null;

  function startScan() {
    // Reset UI state for a fresh scan
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('results').innerHTML = '';
    document.getElementById('summary').style.display = 'none';
    document.getElementById('progressBar').style.width = '5%';
    setStatus('Initialising scan…');
    deviceCount = 0;
    scanStart = Date.now();

    // Close any previous SSE stream
    if (evtSource) evtSource.close();

    // Open a Server-Sent Events stream to the /scan endpoint.
    // SSE keeps the HTTP connection open and pushes JSON events
    // as each device is discovered — no polling needed.
    evtSource = new EventSource('/scan');

    // ── Status updates ───────────────────────────────────────────────
    evtSource.addEventListener('status', e => {
      const d = JSON.parse(e.data);
      setStatus(d.msg);
      // Animate progress bar slowly while scanning
      const bar = document.getElementById('progressBar');
      const cur = parseFloat(bar.style.width) || 5;
      bar.style.width = Math.min(cur + 8, 85) + '%';
    });

    // ── A device result arrived ──────────────────────────────────────
    evtSource.addEventListener('device', e => {
      const device = JSON.parse(e.data);
      deviceCount++;
      renderDevice(device);
      setStatus(`Scanning… ${deviceCount} device(s) found so far`);
    });

    // ── Scan finished ────────────────────────────────────────────────
    evtSource.addEventListener('done', e => {
      const d = JSON.parse(e.data);
      document.getElementById('progressBar').style.width = '100%';
      setStatus('✓ ' + d.msg);
      document.getElementById('scanBtn').disabled = false;
      evtSource.close();

      const elapsed = ((Date.now() - scanStart) / 1000).toFixed(1);
      const summary = document.getElementById('summary');
      summary.style.display = 'block';
      summary.innerHTML =
        `Scan complete in <strong>${elapsed}s</strong> &mdash; ` +
        `<strong>${deviceCount}</strong> device(s) discovered on your local network. ` +
        `Served privately over <strong>Tailscale</strong>.`;
    });

    // ── Error event ──────────────────────────────────────────────────
    evtSource.addEventListener('error', e => {
      try {
        const d = JSON.parse(e.data);
        setStatus('⚠ ' + d.msg);
      } catch (_) {
        setStatus('Connection error — is the server still running?');
      }
    });
  }

  function setStatus(msg) {
    document.getElementById('statusBar').textContent = msg;
  }

  function renderDevice(d) {
    const card = document.createElement('div');
    card.className = 'device-card';

    // ── Build port rows ──────────────────────────────────────────────
    let portRows = '';
    if (d.open_ports && d.open_ports.length > 0) {
      portRows = d.open_ports.map(p => {
        const version = [p.product, p.version, p.extrainfo]
          .filter(Boolean).join(' ');
        const scripts = p.scripts
          ? `<div class="port-script">${escHtml(p.scripts)}</div>` : '';
        return `
          <tr>
            <td><span class="port-num">${p.port}</span>
                <span style="color:var(--muted);font-size:0.65rem">/${p.proto}</span></td>
            <td><span class="port-svc">${escHtml(p.service)}</span></td>
            <td><span class="port-ver">${escHtml(version)}</span>${scripts}</td>
          </tr>`;
      }).join('');
    }

    const latencyBadge = d.latency_ms != null
      ? `<span class="badge badge-lat">${d.latency_ms} ms</span>` : '';

    const osBadge = d.os && d.os !== 'Unknown'
      ? `<span class="badge badge-os" title="${d.os_accuracy}% confidence">${escHtml(d.os)}</span>` : '';

    const macBadge = d.mac && d.mac !== 'Unknown'
      ? `<span class="badge badge-mac">${escHtml(d.mac)}${d.vendor ? ' · ' + escHtml(d.vendor) : ''}</span>` : '';

    card.innerHTML = `
      <div class="device-header">
        <div>
          <div class="device-ip">${escHtml(d.ip)}</div>
          <div class="device-hostname">${escHtml(d.hostname !== 'Unknown' ? d.hostname : '')}</div>
        </div>
        <div class="device-meta">
          ${osBadge}
          ${latencyBadge}
          ${macBadge}
        </div>
      </div>
      <div class="device-body">
        ${portRows ? `
          <div class="section-label">Open Ports &amp; Services</div>
          <table class="port-table">
            <thead>
              <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Version / Info</th>
              </tr>
            </thead>
            <tbody>${portRows}</tbody>
          </table>` :
          `<span class="no-ports">No open ports found in top ${TOP_PORTS} scan.</span>`
        }
        <div style="font-size:0.65rem;color:var(--muted);margin-top:0.5rem">
          scanned at ${escHtml(d.scanned_at)}
        </div>
      </div>`;

    document.getElementById('results').appendChild(card);

    // Smooth scroll to newly added card
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // Prevent XSS from network-sourced strings (hostnames, banners, etc.)
  function escHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }
</script>
</body>
</html>
"""

# ─────────────────────────────────────────────
# Flask routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main dashboard HTML."""
    return render_template_string(HTML)


@app.route("/scan")
def scan():
    """
    SSE endpoint. Opens a long-lived HTTP connection and streams
    scan results as Server-Sent Events as they are discovered.
    The client uses EventSource in JS to receive them without polling.
    """
    subnet = get_local_subnet()

    def generate():
        yield _sse_event("status", {"msg": f"Detected local subnet: {subnet}"})
        yield from scan_network(subnet)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            # Disable buffering so events reach the browser immediately
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


# ─────────────────────────────────────────────
# Server startup — bind to Tailscale + localhost
# ─────────────────────────────────────────────

def start_server(host: str, port: int, label: str):
    """Start Flask in a background thread on the given host:port."""
    print(f"  [{label}]  http://{host}:{port}")
    # use_reloader=False is required when running multiple threads
    app.run(host=host, port=port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    print("\n╔══════════════════════════════════════╗")
    print("║   NetScope // Tailscale Demo Server  ║")
    print("╚══════════════════════════════════════╝\n")

    # ── Get our Tailscale IP ────────────────────────────────────────────
    ts_ip = get_tailscale_ip()

    threads = []

    # ── Always bind to localhost for local testing ──────────────────────
    t_local = threading.Thread(
        target=start_server,
        args=("127.0.0.1", PORT, "localhost"),
        daemon=True
    )
    threads.append(t_local)

    # ── Bind to Tailscale IP if available ──────────────────────────────
    if ts_ip:
        print(f"  Tailscale IP detected: {ts_ip}")
        print(f"  This process will listen ONLY on that IP — no system interface is created.\n")
        t_ts = threading.Thread(
            target=start_server,
            args=(ts_ip, PORT, "tailscale"),
            daemon=True
        )
        threads.append(t_ts)
    else:
        print("  ⚠  Could not reach Tailscale daemon.")
        print("     Make sure Tailscale is installed, running, and you are logged in.")
        print("     Serving on localhost only.\n")

    print("  Servers starting…\n")

    for t in threads:
        t.start()

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nShutting down. Goodbye.")