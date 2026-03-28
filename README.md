# NetScope // Tailscale Demo

> **Credit where due** This project was built as a pair with [Claude](https://claude.ai) (Anthropic) to demonstrate what Tailscale makes possible.

This is live network scanner you can access from your phone, a coffee shop, or the other side of the world — privately, instantly, with no setup beyond installing Tailscale.

---

## Seen in the Wild

*Screenshot taken on my iPhone, connected from a different network via Tailscale — scanning the home LAN where the PC is running:*

![NetScope running on iPhone over Tailscale](https://joelodom.s3.us-east-1.amazonaws.com/IMG_7373.png)

---

## The Tailnet Behind This Demo

Here's the actual setup used to build and test this — three devices on three different networks, all privately connected through one Tailscale tailnet.

**The Windows PC** is on a home network running `tailscale.py`. It has a Tailscale IP of `100.82.151.124` and is visible to every other device in the tailnet.

**The iPhone** is on a completely different network — cellular, a coffee shop, wherever. It has Tailscale installed and logged into the same account. It opens the app over Tailscale in Safari and gets the live scanner UI as if the PC were next door.

**The AWS EC2 instance** is a virtual machine in the cloud, added to the tailnet with a single `tailscale up`. It shows up in the scanner's Tailscale interface scan alongside the local LAN devices, even though it's physically in an AWS data centre. That's the point — the tailnet collapses geography.

---

## The Point of This Demo

This is a totally ordinary Python web server. It binds to `0.0.0.0`, serves an HTML page, and streams scan results over HTTP. There is nothing in the code about Tailscale. No special libraries, no API calls, no configuration.

And yet, the moment Tailscale is running on your PC and your iPhone, you can open this app from your phone from anywhere on the planet as if both devices were sitting on the same desk.

That's the demo. **Tailscale makes your devices behave like they're on the same local network, no matter where they are, and your code doesn't have to do a thing.**

---

## What Gets Scanned

NetScope scans every network interface on your PC simultaneously:

### Your Home LAN
Routers, NAS boxes, printers, smart TVs, game consoles, other PCs. The scanner uses TCP connect probes (not ping) so it finds devices that silently drop ICMP — most phones, smart home gear, and anything with a host firewall.

### Your Tailnet
The Tailscale interface (`100.x.x.x`) is treated as a network just like any other, and NetScope scans a `/24` around your own Tailscale address. Any device on your tailnet — an EC2 instance, a Raspberry Pi, a remote server — appears here right alongside your home router. The EC2 you spun up for this demo shows up in this section.

This is the compelling part: you're scanning a virtual machine running in AWS from your home PC, tunneled privately over WireGuard, discovered the same way as the router plugged into your wall. Tailscale makes it that seamless.

---

## What You'd Normally Have to Do

To expose a local server to your phone when you're away from home, without Tailscale:

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

When devices have Tailscale running, they're part of a private mesh network called a **tailnet**. Each device gets a stable `100.x.x.x` IP that never changes regardless of which network it's on.

Connections are encrypted with **WireGuard**. Tailscale's coordination server introduces devices to each other, then they establish a **direct peer-to-peer link** using NAT traversal — no traffic through Tailscale's servers after the handshake. If a direct path is blocked, traffic routes through Tailscale's **DERP relay servers**, still end-to-end encrypted.

---

## How the Scanner Works

**Discovery:** Each IP is probed against ~24 canary ports (HTTP, SSH, SMB, RDP, printers, iOS sync, MQTT, databases). No ping — TCP only, so devices that silently drop ICMP still get found.

**Port scan:** Every live host gets ports 1–10,000 plus curated high ports (~10,030 total) scanned in parallel.

**Banner grab:** Each open port is read for its opening message — SSH, FTP, SMTP, Redis, and many others announce their software and version on connect.

**Live progress:** Each interface gets its own panel with a discovery progress bar and per-host port-scan progress bars ticking up in real time.

---

## Setup

```powershell
pip install flask
python tailscale.py
```

Open `http://<your-tailscale-ip>:5500` on any tailnet device. Find your Tailscale IP at [login.tailscale.com/admin/machines](https://login.tailscale.com/admin/machines).

---

## Files

```
tailscale.py   — the entire application (server + scanner + UI)
README.md      — this file
```

---

## Security Note

No authentication is implemented. Anyone in your tailnet can reach the dashboard. Tailscale's ACL system in the admin panel lets you restrict access per-device if needed.