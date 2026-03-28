# NetScope // Tailscale Demo

A home network intelligence dashboard that runs on your PC and is privately accessible from any of your devices — anywhere in the world — over your personal Tailscale mesh network.

## Credit Where Credit is Due

The initial version of this script was written entirely by Claude (under my direction) and was then reworked by me.

---

## What This Demonstrates

### The Core Tailscale Concept

Normally, if you want to access a server running on your home PC from your phone while you're out, you'd need to:

- Open ports on your router (port forwarding)
- Set up dynamic DNS (your home IP changes)
- Worry about who else can reach those open ports
- Possibly configure a traditional VPN

**Tailscale eliminates all of this.** It creates a private, encrypted mesh network between your devices — called a *tailnet* — where every device gets a stable `100.x.x.x` IP address. These devices can reach each other directly, as if they were on the same LAN, from anywhere in the world.

This script demonstrates that by running a web server on your PC and making it reachable from your iPhone with zero router configuration.

---

### The Interesting Part: Process-Level Tailscale Binding

Most Tailscale demos work because Tailscale creates a virtual network interface (`utun` on Mac, `tailscale0` on Linux) that the whole OS uses. Any server you run on `0.0.0.0` becomes reachable over Tailscale.

This script does something more precise and more interesting:

**It queries the Tailscale local daemon directly, learns its `100.x.x.x` IP, and binds the Flask server to *only that specific IP*.**

```
┌─────────────────────────────────────────┐
│  Your PC                                │
│                                         │
│  tailscaled (Tailscale daemon)          │
│       │                                 │
│       │  Unix socket (/var/run/         │
│       │  tailscale/tailscaled.sock)     │
│       ▼                                 │
│  tailscale.py ──asks──► "What is my    │
│       │                  Tailscale IP?" │
│       │                                 │
│       ├── binds Flask to 127.0.0.1:5500 (localhost)
│       └── binds Flask to 100.x.x.x:5500 (Tailscale only)
│                                         │
└─────────────────────────────────────────┘
```

The result:

- `http://127.0.0.1:5500` — works on your PC only
- `http://100.x.x.x:5500` — works on any device in your tailnet, from anywhere
- `http://<your-public-home-IP>:5500` — **does not work** (not exposed)
- Anyone on your Wi-Fi (not in your tailnet) — **cannot access it**

This is process-level network isolation. The server is genuinely only reachable through Tailscale's encrypted tunnel.

---

### How Tailscale Makes the Connection

When your iPhone (also running Tailscale) connects to `http://100.x.x.x:5500`, here's what actually happens:

```
iPhone (Tailscale)                    PC (Tailscale)
       │                                    │
       │  WireGuard encrypted packet        │
       │ ─────────────────────────────────► │
       │  (may route via DERP relay         │
       │   if direct UDP is blocked)        │
       │                                    │
       │           HTTP response            │
       │ ◄───────────────────────────────── │
```

- Traffic is encrypted end-to-end with **WireGuard**
- Tailscale handles NAT traversal automatically — no port forwarding needed
- If a direct peer-to-peer connection can't be established, traffic routes through Tailscale's **DERP relay servers**, still encrypted
- Your home router never sees a new open port

---

## What the Scanner Does

Once you hit **Scan Network**, the Python script:

1. **Detects your local subnet** by checking which network interface your PC uses for outbound traffic, then derives a `/24` range (e.g. `192.168.1.0/24`)

2. **Ping sweep** — runs `nmap -sn` to quickly find which IP addresses have live hosts, without touching any ports

3. **Deep scan per host** — for each live host, runs:
   - `-sV` — probes open ports to identify services and their versions
   - `-O` — attempts OS fingerprinting via TCP/IP stack analysis
   - `--top-ports 100` — checks the 100 most commonly used ports
   - NSE scripts: `banner`, `ssh-hostkey`, `http-title`, `smb-os-discovery` for richer detail

4. **Streams results live** using **Server-Sent Events (SSE)** — each device appears on your iPhone as it's discovered, with no page reload

The UI updates in real time as devices are found, making it a genuinely impressive live demo.

---

## Requirements

### System
- **nmap** — [https://nmap.org/download.html](https://nmap.org/download.html)
  - macOS: `brew install nmap`
  - Linux: `sudo apt install nmap`
  - Windows: download the installer; add to PATH
- **Tailscale** — installed and logged in on your PC: [https://tailscale.com/download](https://tailscale.com/download)
- **Python 3.10+**
- Must be run as **root / Administrator** (nmap OS detection requires raw sockets)

### Python packages
```bash
pip install flask python-nmap requests
```

### iPhone
- Install **Tailscale** from the App Store and log in with the same account as your PC
- Open Safari and navigate to `http://<your-tailscale-ip>:5500`
- Find your Tailscale IP in the Tailscale app, or at [https://login.tailscale.com/admin/machines](https://login.tailscale.com/admin/machines)

---

## Running It

```bash
# Linux / macOS
sudo python3 tailscale.py

# Windows (run terminal as Administrator)
python tailscale.py
```

You'll see output like:

```
╔══════════════════════════════════════╗
║   NetScope // Tailscale Demo Server  ║
╚══════════════════════════════════════╝

  Tailscale IP detected: 100.101.102.103
  This process will listen ONLY on that IP — no system interface is created.

  [localhost]   http://127.0.0.1:5500
  [tailscale]   http://100.101.102.103:5500
```

Open `http://100.101.102.103:5500` in Safari on your iPhone (replace with your actual Tailscale IP).

---

## Windows Notes

On Windows, Tailscale's local API is exposed over a named pipe rather than a Unix socket. The `get_tailscale_ip()` function uses a Unix socket adapter and will not work natively on Windows. As a workaround, you can retrieve your Tailscale IP manually:

```powershell
tailscale ip -4
```

Then hard-code it at the top of `tailscale.py`:

```python
ts_ip = "100.x.x.x"  # paste your Tailscale IP here
```

---

## File Structure

```
tailscale.py   — the server (Flask + nmap + Tailscale binding)
README.md      — this file
```

---

## Security Notes

- This server has **no authentication**. Anyone in your tailnet can access it.
- For a production setup, consider adding HTTP Basic Auth or checking the client's Tailscale IP against an allowlist.
- The scanner runs nmap with OS detection, which sends packets to every device on your LAN. Only run this on networks you own or have permission to scan.