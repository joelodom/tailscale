# NetScope // Tailscale Demo

A home network scanner served privately over Tailscale — accessible from your iPhone (or any device) anywhere in the world, with no router configuration, no open ports, and no system-level Tailscale installation.

## Credit Where it's Due

The initial version of this was created in collaboration with Claude.

---

## What This Actually Demonstrates

This project is less about network scanning and more about **how Tailscale works as a connectivity layer**. The scanner is just a reason to have something interesting to look at on your phone. The real demo is the Tailscale part.

---

## The Tailscale Architecture

### No Installation, No Service

Most Tailscale setups install a Windows service (`tailscaled.exe`) that runs in the background at all times. This project skips that entirely.

Instead, `tailscale.py` launches `tailscaled.exe` **directly as a child process**, and when the Python script stops, so does Tailscale. There is no installer, no Windows service entry, no system tray icon, and no entries in `services.msc`. The entire Tailscale node lives and dies with the Python process.

```
python tailscale.py
    │
    ├── spawns ──► tailscaled.exe  (Tailscale daemon, no service)
    │                   │
    │                   └── speaks WireGuard to your tailnet peers
    │
    └── spawns ──► tailscale.exe up  (authenticates, then exits)
```

### Userspace Networking Mode

Normally, Tailscale creates a virtual network adapter — a TUN device. On Windows you'd see a new `Tailscale` interface in `ipconfig`. That interface lets every application on the machine reach your tailnet transparently.

This project uses `--tun=userspace-networking`, which changes the model entirely:

```
Normal Tailscale:
  [App] → [OS network stack] → [Tailscale TUN adapter] → [WireGuard] → [Peer]
                                      ↑
                              visible in ipconfig
                              routes all traffic

Userspace Tailscale (this project):
  [Flask server] → [bound to Tailscale IP] → [WireGuard in tailscaled.exe] → [Peer]
                         ↑
                    only this process
                    nothing else uses it
```

In userspace mode, Tailscale implements the entire WireGuard tunnel inside the `tailscaled.exe` process. No kernel driver is involved. Nothing in `ipconfig` changes. No other application on the PC can route traffic through the Tailscale network — only the services that explicitly bind to the Tailscale IP address can be reached.

This is a meaningful security distinction: the surface area exposed through Tailscale is exactly and only the Flask server on port 5500.

### Portable State Directory

The Tailscale node's identity — its private key, auth tokens, and peer certificates — is stored in `./tailscale-state/` rather than `C:\ProgramData\Tailscale`. This makes the whole setup self-contained and portable.

```
NetScope/
├── tailscale.py
├── tailscale.exe
├── tailscaled.exe
└── tailscale-state/       ← node identity, keys, auth tokens
    ├── tailscaled.state
    └── ...
```

First run: `tailscale-state/` is empty, so the node authenticates from scratch (browser login). Subsequent runs: the saved state means silent reconnect — no login required.

Delete `tailscale-state/` and the node starts fresh with a new identity.

### The LocalAPI Named Pipe

After `tailscaled.exe` starts, Python needs to know what Tailscale IP was assigned to this node. It gets this by talking to tailscaled's **LocalAPI** — a plain HTTP/1.1 API served over a Windows named pipe.

```python
# Open the named pipe
pipe = win32file.CreateFile(
    r"\\.\pipe\ProtectedPrefix\Administrators\Tailscale\tailscaled",
    GENERIC_READ | GENERIC_WRITE, ...
)

# Send a plain HTTP request over it
win32file.WriteFile(pipe, b"GET /localapi/v0/status HTTP/1.0\r\n...")

# Parse the JSON response
data = json.loads(response_body)
ts_ip = data["Self"]["TailscaleIPs"][0]   # → "100.x.x.x"
```

This is the same pipe the official Tailscale GUI and CLI use. It never leaves the machine — it's local IPC, not a network call. The `pywin32` library (the only dependency beyond Flask) gives Python access to the Win32 named pipe API.

### Binding Flask to the Tailscale IP

Once the Tailscale IP is known, Flask is bound to two addresses in parallel threads:

```python
# Always available for local testing
threading.Thread(target=app.run, kwargs={"host": "127.0.0.1", "port": 5500}).start()

# Only reachable through Tailscale
threading.Thread(target=app.run, kwargs={"host": "100.x.x.x", "port": 5500}).start()
```

This means:

| Address | Reachable from |
|---|---|
| `http://127.0.0.1:5500` | This PC only |
| `http://100.x.x.x:5500` | Any device on your tailnet |
| `http://<public-home-IP>:5500` | **Nobody** — not exposed |
| Any device on your Wi-Fi (not in tailnet) | **Nobody** |

The router is never involved. No port is opened. The only path to the server is through Tailscale's encrypted WireGuard tunnel.

### How Your iPhone Connects

When you open `http://100.x.x.x:5500` in Safari on your iPhone (which has Tailscale installed and logged in to the same account):

```
iPhone (Tailscale running)
    │
    │  WireGuard encrypted UDP packet
    │  (direct peer-to-peer if possible,
    │   or via Tailscale DERP relay if NAT blocks it)
    ▼
Your PC (tailscaled.exe running in userspace mode)
    │
    │  decrypts packet, routes to Flask
    ▼
Flask server → HTML response → back through WireGuard → your iPhone
```

Tailscale handles NAT traversal automatically using the same techniques as WebRTC (STUN/TURN). If a direct UDP path exists between your iPhone and PC, it uses that. If NAT blocks it (e.g., a strict corporate firewall), traffic routes through Tailscale's DERP relay servers — still end-to-end encrypted, just with a relay in the middle.

Either way, the connection works from anywhere: your home network, a coffee shop, a hotel, a cellular connection.

---

## Setup

### 1. Download the Tailscale binaries

Go to [pkgs.tailscale.com/stable/#windows-amd64](https://pkgs.tailscale.com/stable/#windows-amd64) and download the latest Windows AMD64 zip. Extract `tailscaled.exe` and `tailscale.exe` into the same folder as `tailscale.py`.

### 2. Install Python dependencies

```powershell
pip install flask pywin32
```

`flask` — serves the web UI.  
`pywin32` — provides access to the Windows named pipe API so Python can talk to tailscaled's LocalAPI.

Everything else (network scanning, JSON, threading, subprocess) is Python stdlib.

### 3. Install Tailscale on your iPhone

Download the Tailscale app from the App Store and sign in with the same account you'll use on your PC. Both devices need to be on the same tailnet.

### 4. Run

```powershell
python tailscale.py
```

On first run, a browser window opens for Tailscale login. Sign in once and subsequent runs connect silently.

The terminal will print two URLs when ready:

```
  [localhost  ]  http://127.0.0.1:5500
  [tailscale  ]  http://100.101.102.103:5500
```

Open the second URL in Safari on your iPhone.

---

## File Layout

```
NetScope/
├── tailscale.py          ← the whole application
├── tailscale.exe         ← Tailscale CLI (you provide)
├── tailscaled.exe        ← Tailscale daemon (you provide)
├── tailscale-state/      ← created on first run, keeps you logged in
└── README.md
```

---

## Security Notes

- **No authentication** is implemented. Anyone in your tailnet can reach the dashboard. For a personal demo this is fine; for anything shared, add HTTP Basic Auth.
- The scanner uses TCP connect probes and ICMP ping — normal, non-destructive discovery. Only scan networks you own or have permission to scan.
- Tailscale's access controls (ACLs) in the admin panel let you restrict which tailnet devices can reach which others, if needed.