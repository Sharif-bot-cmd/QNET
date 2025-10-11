# 🌐 QNET: Hybrid Decentralized Web Node

## What’s New in QNET 1.4

- Cached `state.json` allows instant boot using last known mode.
- Background network probing (IPFS, I2P, TOR) runs asynchronously.
- Full offline support with cached state and deferred sync.
- Parallel detection for IPFS / I2P / TOR (`detect_mode()` upgraded).
- Auto-starts local daemons if not running.
- Multi-mode support (`MULTI`) for hybrid networks.
- Each QNET node now generates its own cryptographic identity.
- Based on [NaCl (libsodium)](https://pynacl.readthedocs.io/) signing keys.
- Stored locally in `did.json`.
- Used to verify authenticity of posts, uploads, and peer syncs.
- New **LAN broadcast discovery** (`announce_peer()` + `listen_for_peers()`).
- Automatic peer merging — no manual editing of `peers.json`.
- `/api/sync` endpoint allows nodes to exchange databases directly.
- Background sync thread runs continuously without blocking UI.
- Automatic JSON database backup every 6 hours (`/backups/`).
- Integrity check & recovery if corruption is detected.
- Fully offline repair cycle with no external dependencies.
- Filename sanitization on uploads (no traversal or injection).
- Simple IP-based rate limiter (30 requests/minute per client).
- Thread-safe state saving with atomic `.tmp` write replacement.
- Live decentralized status badge at bottom-left of every page.

---

## ✨ Why QNET Stands Out

Modern web platforms rely on centralized data centers and third-party APIs.  
QNET removes that dependency, letting anyone host their own mini web node, private when desired, global when chosen.

It combines edge computing, local-first design, and network autonomy in a single package.

---

## 🚀 Key Features

- **Hybrid Network Modes**
  - Offline, I2P, TOR, or IPFS auto-detection.
  - Global access via Cloudflare or Ngrok tunnels.

- **Secure File System**
  - Upload, share, and stream files (videos, posts, leaks).
  - Each item is hashed and optionally mirrored to IPFS.

- **Built-in Security Levels**
  - 🟢 **Standard**: Global tunnels active  
  - 🟡 **Safer**: Encrypted peers only  
  - 🔴 **Safest**: Fully offline, no external tunnels

- **Web Dashboard**
  - Terminal-inspired green-on-black interface.
  - Fully responsive and local-first.

- **Cross-Platform Support**
  - Runs seamlessly on Android (Termux), Linux, macOS, Windows, etc.

> ⚠️ **Note:** IPFS mirror requires a running IPFS daemon (`ipfs daemon`) to access content locally.

---

## 🔒 Privacy & Security

- No external tracking or analytics.  
- Optional offline mode ensures complete privacy.  
- Security levels let you choose between fully offline or global accessibility.  
- Data files are hashed and stored locally; optional mirroring to IPFS does not expose your identity.  

---

## 🧰 Installation & Setup

QNET 1.0 is cross-platform and runs on **Linux**, **Android (Termux)**, **macOS**, and **Windows (via WSL or Git Bash)**.

Before running QNET, make sure you have:
- Python 3.10+  
- pip (Python package manager)  
- IPFS  
- curl  
- wget  

---

### 🔧 Quick Setup (Recommended)

QNET includes an automatic environment setup script that installs all dependencies for you.

Run this command from the project folder:
---
bash setup.sh

## 📚 Usage

1. Run qnet.py (online/offline)
---
python qnet.py

3. Ensure your IPFS daemon is running for local content:  
---
ipfs daemon

4. Open your preferred mirror

Local: http://127.0.0.1:8080

IPFS: http://127.0.0.1:8081/ipfs/QmSk6tx2phgMny2guUoSgYdBXgMuWCPXT3ppJY8NYGqiLZ

Cloudflare/Ngrok tunnel (auto-generated)

5. Upload files (videos, posts, leaks) via the dashboard.

6. Upload & Manage Content

Upload files under Videos, Posts, or Leaks.

Share IPFS or Cloudflare links directly.

7. Adjust Security Level

Use Settings → Security Level to switch between Standard, Safer, or Safest.

## 🪙 Bitcoin Donations

QNET is a passion-driven, open-source decentralized web node.
If you’d like to support development, maintenance, and infrastructure, you can donate Bitcoin directly:

Bitcoin Address:
bc1qpcaqkzpe028ktpmeyevwdkycg9clxfuk8dty5v

Every contribution helps maintain a censorship-resistant, privacy-first ecosystem.
Thank you for keeping QNET decentralized 🌍

⚡ Contributing

QNET is open-source and welcomes contributions that improve privacy, performance, and cross-platform compatibility.

Fork the repository

Submit pull requests for bug fixes or feature enhancements

Respect privacy-first principles

Created & maintained by:
Sharif Muhaymin

Decentralized Systems & Edge Autonomy Advocate
