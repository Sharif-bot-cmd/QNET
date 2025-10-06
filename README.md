# 🌐 QNET 1.0: Hybrid Decentralized Web Node

QNET is a self-contained, privacy-first micro network that transforms your device into a decentralized web portal — capable of operating **offline**, through **I2P/TOR/IPFS**, or globally via **Cloudflare Tunnel** or **Ngrok**.

It’s lightweight, fast, and designed to run anywhere — from Linux and Android (Termux) to macOS or Windows.

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

## 📚 Usage

1. Run qnet.py (online/offline)
---
python qnet.py

3. Ensure your IPFS daemon is running for local content:  
---
ipfs daemon

4. Open your preferred mirror

Local: http://127.0.0.1:8080

IPFS: http://127.0.0.1:8081/ipfs/QmPYqvQasLwy3zkwKhoY6FmHT9dXSSuL5FKrjdx1g8Geyr

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
