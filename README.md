# NetScope // Tailscale Demo

A live home network scanner you can access from your phone, a coffee shop, or the other side of the world — privately, instantly, with no setup beyond installing Tailscale.

---

## The Point of This Demo

This is a totally ordinary Python web server. It binds to `0.0.0.0`, serves an HTML page, and streams scan results over HTTP. There is nothing in the code about Tailscale. No special libraries, no API calls, no configuration.

And yet, the moment Tailscale is running on your PC and your iPhone, you can open this app from your phone from anywhere on the planet as if both devices were sitting on the same desk.

That's the demo. **Tailscale makes your devices behave like they're on the same local network, no matter where they are, and your code doesn't have to do a thing.**

---

## What You'd Normally Have to Do

To expose a local server to your phone when you're away from home, without Tailscale, you'd need to:

1. Log into your router and set up port forwarding
2. Figure out your home's public IP address (which changes)
3. Set up dynamic DNS so you have a stable hostname
4. Hope your ISP doesn't block inbound connections
5. Open a firewall hole and accept the exposure to the public internet
6. Do it all again if you move or change ISPs

With Tailscale:

1. Install Tailscale on both devices and sign in

That's the list.

---

## How Tailscale Actually Works

When both devices have Tailscale running, they're part of a private mesh network called a **tailnet**. Each device gets a stable `100.x.x.x` IP address that never changes, regardless of what network it's on. Your PC is `100.x.x.x`. Your iPhone is `100.y.y.y`. They can always reach each other.

The connection is encrypted with **WireGuard**, which is a modern, audited, extremely lean VPN protocol built into the Linux kernel and available on all major platforms. Tailscale uses WireGuard under the hood for every connection.

To establish the connection between devices that are behind NAT (which is almost everything — home routers, mobile data, coffee shop Wi-Fi), Tailscale uses a coordination server to introduce devices to each other, then tries to establish a **direct peer-to-peer link** using techniques similar to WebRTC. In most cases, the two devices end up talking directly to each other — Tailscale's servers are only involved in the handshake. If a direct path isn't possible (very strict firewalls), traffic routes through Tailscale's **DERP relay servers**, still end-to-end encrypted so Tailscale can't read it.

The result is that from your iPhone's perspective, your home PC is just a device at `100.x.x.x` that it can reach with ordinary HTTP. No different from being on the same Wi-Fi.

---

## Running the Demo

### 1. Install Tailscale

Download and install Tailscale on your Windows PC: [tailscale.com/download](https://tailscale.com/download)

Sign in. That's it — the service starts automatically and your PC joins your tailnet.

### 2. Install Tailscale on your iPhone

Install the Tailscale app from the App Store. Sign in with the same account. Your iPhone now appears in your tailnet alongside your PC.

### 3. Find your PC's Tailscale IP

Open the Tailscale system tray icon, or go to [login.tailscale.com/admin/machines](https://login.tailscale.com/admin/machines). Your PC will have a `100.x.x.x` address listed.

### 4. Install the one Python dependency and run

```powershell
pip install flask
python tailscale.py
```

### 5. Open it on your iPhone

In Safari, navigate to:

```
http://100.x.x.x:5500
```

(Replace with your actual Tailscale IP.)

It works. From anywhere. No router config. No firewall rules. No port forwarding.

---

## What the App Does

Hit **Scan Network** and the server scans your home LAN in real time:

- **Ping sweep** — finds all live hosts on the subnet
- **Port scan** — probes the 150 most common TCP ports per host, in parallel
- **Banner grab** — reads each open service's opening message (reveals software names and versions for SSH, FTP, SMTP, Redis, and many others)
- **Reverse DNS** — resolves hostnames where available
- **Device type guess** — infers what kind of device it is from the combination of open ports and hostname

Results stream to your phone live as each host is finished — you don't wait for the whole scan to complete.

The scanner uses only Python's standard library. No nmap, no third-party network libraries.

---

## Security Note

This server has no authentication. Anyone in your tailnet can reach it. For a personal demo that's fine. If you share your tailnet with others, Tailscale's ACL system (in the admin panel) lets you restrict which devices can reach which others.

---

## Files

```
tailscale.py   — the entire application (server + scanner + UI)
README.md      — this file
```