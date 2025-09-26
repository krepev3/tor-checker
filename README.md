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


Configure Tor

Edit /etc/tor/torrc and add the following configuration:

SocksPort 9050
ControlPort 9051

# Cookie auth is simplest & safest
CookieAuthentication 1
CookieAuthFile /run/tor/control.authcookie
CookieAuthFileGroupReadable 1

# (optional) Better stream isolation
SocksPort 9050 IsolateSOCKSAuth IsolateDestAddr IsolateDestPort

# (default, usually present)
DataDirectory /var/lib/tor

sudo systemctl restart tor
sudo systemctl enable tor

Authentication Options
Option A: Cookie Authentication (recommended)

sudo usermod -aG debian-tor $USER
newgrp debian-tor
ls -l /run/tor/control.authcookie

Option B: Password Authentication (fallback)

tor --hash-password "YourPass"

Add the hash to /etc/tor/torrc:
HashedControlPassword <hash>


Save plaintext password in ~/.config/check-tor.conf:
mkdir -p ~/.config
echo 'CONTROL_PASSWORD=YourPass' > ~/.config/check-tor.conf
chmod 600 ~/.config/check-tor.conf

Optional Per-User Config

File: ~/.config/check-tor.conf
SOCKS_HOST=127.0.0.1
SOCKS_PORT=9050
CONTROL_HOST=127.0.0.1
CONTROL_PORT=9051
TOR_SERVICE=tor
CACHE_DIR="$HOME/.cache/check-tor"
# CONTROL_PASSWORD=...


Install Script

chmod +x check-tor
sudo install -m 0755 check-tor /usr/local/bin/check-tor

Usage
Non-interactive flags:

check-tor --verify        # Quick service + exit IP check + SAFE METER
check-tor --newnym        # Rotate Tor circuit
check-tor --show-ips      # Direct vs Tor IPs + country
check-tor --score         # SAFE METER only
check-tor --json          # JSON status
check-tor --fix-controlport  # Auto-fix torrc + restart (root)

Interactive menu:
check-tor



