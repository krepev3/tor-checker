# tor-checker  
Convenient Tor Checker for non-Tor Browser environments.  
A Bash utility to quickly verify Tor connectivity, rotate circuits, check for DNS leaks, and measure anonymity strength (SAFE METER).

---

## ✨ Features
- Show direct vs Tor IPs (IPv4/IPv6 + country lookup)
- Quick Tor verification (service, SOCKS, torsocks, exit IPs)
- SAFE METER (0–100%) with status bar
- NEWNYM support (via ControlPort / cookie / password / empty auth, fallback to SIGHUP)
- DNS leak test (Cloudflare DoH endpoints over Tor)
- Stream isolation hint for advanced configs
- JSON output for scripts / automation
- Interactive menu or non-interactive flags

---

## 🚀 Step-by-Step Setup

### 1. Install Dependencies
On Debian/Ubuntu/Kali:
```bash
sudo apt update
sudo apt install -y tor torsocks curl ca-certificates iproute2 \
  netcat-openbsd vim-common
