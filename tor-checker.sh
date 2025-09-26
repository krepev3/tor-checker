#!/usr/bin/env bash
# check-tor — Tor verification & control helper
# Version: v1.6 (2025-09-25)
# - Auto-loads secret from ~/.config/check-tor.conf (CONTROL_PASSWORD)
# - Anonymity SAFE METER (0–100) + bar
# - Robust cookie auth (0xHEX attempt, then quoted-hex fallback), then password, then empty
# - Keeps: IPv4/IPv6 + country via Tor (cached), NEWNYM via ControlPort, DNS leak test, JSON/flags, menu

set -Eeo pipefail     # (no -u; avoid nounset crashes)

# ---------- Auto-load per-user secret config (600 perms recommended) ----------
CONFIG_FILE="${HOME:-/root}/.config/check-tor.conf"
if [[ -f "$CONFIG_FILE" ]]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
fi

# ---------- Defaults ----------
SOCKS_HOST="${SOCKS_HOST:-127.0.0.1}"
SOCKS_PORT="${SOCKS_PORT:-9050}"
CONTROL_HOST="${CONTROL_HOST:-127.0.0.1}"
CONTROL_PORT="${CONTROL_PORT:-9051}"
TOR_SERVICE="${TOR_SERVICE:-tor}"
CACHE_DIR="${CACHE_DIR:-$HOME/.cache/check-tor}"

divider="==========================================="
mkdir -p "$CACHE_DIR"

# ---------- Colors ----------
if [[ -t 1 ]]; then
  C_OK="\033[1;32m"; C_WARN="\033[1;33m"; C_FAIL="\033[1;31m"; C_INFO="\033[1;34m"; C_RST="\033[0m"
else
  C_OK=""; C_WARN=""; C_FAIL=""; C_INFO=""; C_RST=""
fi
ok(){   echo -e "${C_OK}[OK]${C_RST} $*"; }
warn(){ echo -e "${C_WARN}[WARN]${C_RST} $*"; }
fail(){ echo -e "${C_FAIL}[FAIL]${C_RST} $*"; }
info(){ echo -e "${C_INFO}[INFO]${C_RST} $*"; }

# ---------- Utilities (no jq) ----------
json_get(){ local key="${1-}"; sed -n "s/.*\"${key}\":[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" | head -n1; }
cache_get(){ local k="${1-}"; [[ -n "$k" && -f "$CACHE_DIR/$k" ]] && cat "$CACHE_DIR/$k"; }
cache_put(){ local k="${1-}" v="${2-}"; [[ -n "$k" ]] && printf "%s" "${v-}" > "$CACHE_DIR/$k"; }

# ---------- Geo lookup via Tor (cached, ip-api free tier) ----------
get_country(){
  local ip="${1-}" key resp country
  [[ -z "$ip" || "$ip" == "N/A" ]] && { echo "Unknown"; return; }
  key="cc_${ip}"
  local hit; hit="$(cache_get "$key" || true)"
  if [[ -n "$hit" ]]; then echo "$hit"; return; fi
  resp="$(curl -m 8 -s --socks5-hostname "${SOCKS_HOST}:${SOCKS_PORT}" "http://ip-api.com/json/${ip}?fields=country" 2>/dev/null || true)"
  country="$(echo "$resp" | json_get country)"
  [[ -z "${country}" ]] && country="Unknown"
  cache_put "$key" "$country"
  echo "$country"
}

get_direct_ip4(){ curl -m 5 -s4 https://ifconfig.me 2>/dev/null || true; }
get_direct_ip6(){ curl -m 5 -s6 https://ifconfig.me 2>/dev/null || true; }

get_tor_ip_v(){ # $1 = 4 or 6
  local ver="${1-4}" resp ip
  resp="$(curl -m 8 -s${ver} --socks5-hostname "${SOCKS_HOST}:${SOCKS_PORT}" https://check.torproject.org/api/ip 2>/dev/null || true)"
  ip="$(echo "${resp}" | json_get IP)"
  [[ -n "${ip}" ]] && echo "${ip}" || echo "N/A"
}

show_ips(){
  local d4 d6 t4 t6 d4c d6c t4c t6c
  d4="$(get_direct_ip4)"; [[ -z "${d4}" ]] && d4="N/A"
  d6="$(get_direct_ip6)"; [[ -z "${d6}" ]] && d6="N/A"
  t4="$(get_tor_ip_v 4)"; t6="$(get_tor_ip_v 6)"
  d4c="$(get_country "${d4}")"; d6c="$(get_country "${d6}")"
  t4c="$(get_country "${t4}")"; t6c="$(get_country "${t6}")"
  echo "[Direct IP] IPv4: ${d4} (${d4c}) | IPv6: ${d6} (${d6c})"
  echo "[Tor IP]    IPv4: ${t4} (${t4c}) | IPv6: ${t6} (${t6c})"
}

verify_http_200(){
  local ver="${1-4}"
  curl -m 8 -s${ver} --socks5-hostname "${SOCKS_HOST}:${SOCKS_PORT}" -o /dev/null -w "%{http_code}" https://check.torproject.org 2>/dev/null || echo ""
}

# ---------- Anonymity Score / SAFE METER ----------
anonymity_score(){
  local score=0

  # Service
  systemctl is-active --quiet "${TOR_SERVICE}" && ((score+=10))

  # SOCKS listener
  ss -tlnp 2>/dev/null | grep -qE "[[:space:]]${SOCKS_HOST}:${SOCKS_PORT}[[:space:]]" && ((score+=30))

  # curl via Tor (v4/v6)
  [[ "$(verify_http_200 4)" == "200" ]] && ((score+=20))
  [[ "$(verify_http_200 6)" == "200" ]] && ((score+=10))

  # torsocks
  if command -v torsocks >/dev/null 2>&1; then
    torsocks curl -m 6 -s -o /dev/null -w "%{http_code}" https://check.torproject.org 2>/dev/null | grep -q "200" && ((score+=20))
  fi

  # Exit IP different from direct (v4)
  local d4="$(get_direct_ip4)"; local t4="$(get_tor_ip_v 4)"
  [[ -n "$d4" && -n "$t4" && "$d4" != "$t4" ]] && ((score+=10))

  # Bar
  local filled=$((score/5)) empty=$((20-filled))
  local bar
  bar="$(printf '█%.0s' $(seq 1 "$filled"))$(printf '░%.0s' $(seq 1 "$empty"))"

  # Status
  local status="Unsafe"
  ((score>=90)) && status="Fully Anonymous"
  ((score>=70 && score<90)) && status="Anonymous (Good)"
  ((score>=40 && score<70)) && status="Partial (Leaky)"

  echo -e "\n[SAFE METER] ${bar}  ${score}% — ${status}"
}

# ---------- Verify ----------
verify_tor(){
  echo "=== Tor quick verify — $(date -u +%FT%TZ) ==="
  systemctl is-active --quiet "${TOR_SERVICE}" && ok "tor.service active" || fail "tor.service not running"

  if ss -tlnp 2>/dev/null | grep -qE "[[:space:]]${SOCKS_HOST}:${SOCKS_PORT}[[:space:]]"; then
    ok "SOCKS on ${SOCKS_HOST}:${SOCKS_PORT}"
  else
    fail "No SOCKS listener on ${SOCKS_HOST}:${SOCKS_PORT}"
  fi

  [[ "$(verify_http_200 4)" == "200" ]] && ok "curl via SOCKS (IPv4) HTTP 200" || warn "curl via SOCKS (IPv4) failed"
  [[ "$(verify_http_200 6)" == "200" ]] && ok "curl via SOCKS (IPv6) HTTP 200" || warn "curl via SOCKS (IPv6) failed"

  if command -v torsocks >/dev/null 2>&1; then
    if torsocks curl -m 8 -s -o /dev/null -w "%{http_code}" https://check.torproject.org 2>/dev/null | grep -q "200"; then
      ok "torsocks works (HTTP 200)"
    else
      warn "torsocks failed (check /etc/tor/torsocks.conf)"
    fi
  else
    info "torsocks not installed (optional)"
  fi

  local ip4 ip6 c4 c6
  ip4="$(get_tor_ip_v 4)"; ip6="$(get_tor_ip_v 6)"
  c4="$(get_country "${ip4}")"; c6="$(get_country "${ip6}")"
  if [[ "${ip4}" != "N/A" || "${ip6}" != "N/A" ]]; then
    ok "Tor exit IPs — IPv4: ${ip4} (${c4}) | IPv6: ${ip6} (${c6})"
  else
    fail "Could not fetch any Tor exit IP"
  fi

  anonymity_score
}

# ---------- ControlPort / NEWNYM ----------
nc_send(){ printf "%b" "${3-}" | nc -w 3 "${1-}" "${2-}" 2>/dev/null || true; }
controlport_listening(){ ss -tlnp 2>/dev/null | grep -qE "[[:space:]]${CONTROL_HOST}:${CONTROL_PORT}[[:space:]]"; }

# Try cookie auth (0xHEX first, then quoted hex fallback)
try_auth_cookie(){
  local p cookie_hex
  for p in /run/tor/control.authcookie /var/run/tor/control.authcookie /var/lib/tor/control_auth_cookie; do
    if [[ -r "$p" ]]; then
      cookie_hex="$(xxd -p -c 256 "$p" 2>/dev/null | tr -d '\n\r' || true)"
      [[ -n "$cookie_hex" ]] && break
    fi
  done
  [[ -z "$cookie_hex" ]] && return 1

  # 1) 0xHEX (preferred)
  if nc_send "${CONTROL_HOST}" "${CONTROL_PORT}" "AUTHENTICATE 0x${cookie_hex}\r\nQUIT\r\n" | grep -q "250 OK"; then
    return 0
  fi
  # 2) quoted hex fallback
  nc_send "${CONTROL_HOST}" "${CONTROL_PORT}" "AUTHENTICATE \"${cookie_hex}\"\r\nQUIT\r\n" | grep -q "250 OK"
}

try_auth_password(){
  [[ -z "${CONTROL_PASSWORD:-}" ]] && return 1
  nc_send "${CONTROL_HOST}" "${CONTROL_PORT}" "AUTHENTICATE \"${CONTROL_PASSWORD}\"\r\nQUIT\r\n" | grep -q "250 OK"
}

try_auth_empty(){
  nc_send "${CONTROL_HOST}" "${CONTROL_PORT}" "AUTHENTICATE \"\"\r\nQUIT\r\n" | grep -q "250 OK"
}

send_newnym(){
  if ! controlport_listening; then
    warn "ControlPort ${CONTROL_HOST}:${CONTROL_PORT} not listening; try --fix-controlport"
    pkill -HUP -x tor 2>/dev/null && ok "SIGHUP sent to tor (fallback)" || fail "Could not signal tor"
    return
  fi

  local method=""
  if try_auth_cookie; then method="COOKIE"
  elif try_auth_password; then method="PASSWORD"
  elif try_auth_empty; then method="EMPTY"
  else
    warn "ControlPort auth failed; use --fix-controlport or set CONTROL_PASSWORD"
    pkill -HUP -x tor 2>/dev/null && ok "SIGHUP sent to tor (fallback)" || fail "Could not signal tor"
    return
  fi

  local payload="" cookie_hex=""
  case "$method" in
    COOKIE)
      for p in /run/tor/control.authcookie /var/run/tor/control.authcookie /var/lib/tor/control_auth_cookie; do
        [[ -r "$p" ]] && { cookie_hex="$(xxd -p -c 256 "$p" 2>/dev/null | tr -d '\n\r' || true)"; [[ -n "$cookie_hex" ]] && break; }
      done
      # prefer 0xHEX authenticate
      payload="AUTHENTICATE 0x${cookie_hex}\r\nSIGNAL NEWNYM\r\nQUIT\r\n"
      ;;
    PASSWORD)
      payload="AUTHENTICATE \"${CONTROL_PASSWORD}\"\r\nSIGNAL NEWNYM\r\nQUIT\r\n"
      ;;
    EMPTY)
      payload="AUTHENTICATE \"\"\r\nSIGNAL NEWNYM\r\nQUIT\r\n"
      ;;
  esac

  if nc_send "${CONTROL_HOST}" "${CONTROL_PORT}" "$payload" | grep -q "250 OK"; then
    ok "NEWNYM sent via ControlPort (${method})"
  else
    warn "NEWNYM via ControlPort failed; using SIGHUP"
    pkill -HUP -x tor 2>/dev/null && ok "SIGHUP sent to tor (fallback)" || fail "Could not signal tor"
  fi
}

# ---------- DNS leak test ----------
dns_leak_test(){
  echo "=== DNS leak test — $(date -u +%FT%TZ) ==="
  local st4 st6
  st4="$(curl -m 8 -s4 --socks5-hostname "${SOCKS_HOST}:${SOCKS_PORT}" https://1.1.1.1/cdn-cgi/trace 2>/dev/null | grep '^ip=' || true)"
  st6="$(curl -m 8 -s6 --socks5-hostname "${SOCKS_HOST}:${SOCKS_PORT}" https://[2606:4700:4700::1111]/cdn-cgi/trace 2>/dev/null | grep '^ip=' || true)"
  [[ -n "$st4" ]] && ok "DoH via Tor (IPv4) — $st4" || warn "DoH via Tor (IPv4) failed"
  [[ -n "$st6" ]] && ok "DoH via Tor (IPv6) — $st6" || warn "DoH via Tor (IPv6) failed"
  info "Use curl --socks5-hostname (already used here) to avoid local DNS."
}

# ---------- Isolation hint ----------
isolation_hint(){
  info "For strong stream isolation, add to /etc/tor/torrc then restart Tor:"
  echo "  SocksPort 9050 IsolateSOCKSAuth IsolateDestAddr IsolateDestPort"
}

# ---------- Auto-fix ControlPort ----------
fix_controlport(){
  local TORRC="/etc/tor/torrc" BK="$TORRC.bak-$(date -u +%FT%TZ)"
  if [[ $EUID -ne 0 ]]; then fail "Run --fix-controlport as root (sudo)"; return 1; fi
  cp -a "$TORRC" "$BK" || true
  info "Backup saved at $BK"
  ensure() {
    local key="$1" val="$2"
    if grep -Eq "^[[:space:]]*#?[[:space:]]*$key\\b" "$TORRC"; then
      sed -i -E "s|^[[:space:]]*#?[[:space:]]*$key\\b.*|$key $val|g" "$TORRC"
    else
      printf "\n$key %s\n" "$val" >>"$TORRC"
    fi
  }
  ensure "SocksPort" "9050"
  ensure "ControlPort" "9051"
  ensure "CookieAuthentication" "1"
  ensure "CookieAuthFile" "/run/tor/control.authcookie"
  ensure "CookieAuthFileGroupReadable" "1"
  ensure "DataDirectory" "/var/lib/tor"

  systemctl restart tor || { fail "tor restart failed"; return 1; }
  sleep 1

  if ss -tlnp 2>/dev/null | grep -qE "[[:space:]]127\.0\.0\.1:9051[[:space:]]"; then
    ok "ControlPort is listening on 127.0.0.1:9051"
  else
    fail "ControlPort not listening; check $TORRC syntax"
    return 1
  fi

  local ck=""
  ck="$(xxd -p -c 256 /run/tor/control.authcookie 2>/dev/null | tr -d '\n\r' || \
       xxd -p -c 256 /var/run/tor/control.authcookie 2>/dev/null | tr -d '\n\r' || \
       xxd -p -c 256 /var/lib/tor/control_auth_cookie 2>/dev/null | tr -d '\n\r' || true)"
  if [[ -z "$ck" ]]; then
    warn "Cookie not readable; ensure tor created it and permissions are OK"
  else
    if printf 'AUTHENTICATE 0x%s\r\nQUIT\r\n' "$ck" | nc -w 2 127.0.0.1 9051 2>/dev/null | grep -q "250 OK"; then
      ok "Cookie authentication works"
    else
      warn "Cookie authentication failed; consider HashedControlPassword"
    fi
  fi
}

# ---------- JSON mode ----------
emit_json(){
  local d4 d6 t4 t6 d4c d6c t4c t6c svc sock
  d4="$(get_direct_ip4)"; [[ -z "$d4" ]] && d4="N/A"
  d6="$(get_direct_ip6)"; [[ -z "$d6" ]] && d6="N/A"
  t4="$(get_tor_ip_v 4)"; t6="$(get_tor_ip_v 6)"
  d4c="$(get_country "$d4")"; d6c="$(get_country "$d6")"
  t4c="$(get_country "$t4")"; t6c="$(get_country "$t6")"
  svc="$(systemctl is-active "${TOR_SERVICE}" >/dev/null 2>&1 && echo active || echo inactive)"
  sock="$(ss -tlnp 2>/dev/null | grep -qE "[[:space:]]${SOCKS_HOST}:${SOCKS_PORT}[[:space:]]" && echo yes || echo no)"
  printf '{"service":"%s","socks":"%s","direct":{"ipv4":"%s","ipv6":"%s","c4":"%s","c6":"%s"},"tor":{"ipv4":"%s","ipv6":"%s","c4":"%s","c6":"%s"}}\n' \
    "$svc" "$sock" "$d4" "$d6" "$d4c" "$d6" "$t4" "$t6" "$(get_country "$t4")" "$(get_country "$t6")"
}

# ---------- Non-interactive flags ----------
if [[ "${1-}" =~ ^--set-socks= ]]; then
  val="${1#--set-socks=}"; SOCKS_HOST="${val%:*}"; SOCKS_PORT="${val#*:}"
  ok "SOCKS set to ${SOCKS_HOST}:${SOCKS_PORT}"; exit 0
elif [[ "${1-}" == "--show-ips" ]]; then show_ips; exit 0
elif [[ "${1-}" == "--verify"   ]]; then verify_tor; exit 0
elif [[ "${1-}" == "--newnym"   ]]; then send_newnym; exit 0
elif [[ "${1-}" =~ ^--monitor=  ]]; then secs="${1#--monitor=}"; while true; do show_ips; sleep "${secs:-10}"; done; exit 0
elif [[ "${1-}" == "--json"     ]]; then emit_json; exit 0
elif [[ "${1-}" == "--fix-controlport" ]]; then fix_controlport; exit $?
elif [[ "${1-}" == "--score"    ]]; then anonymity_score; exit 0
fi

# ---------- Menu ----------
show_help(){
  cat <<EOF
${divider}
[1] Show direct vs Tor IPs (IPv4+IPv6 + country)
[2] Tor verification (full) + SAFE METER
[3] NEWNYM (rotate circuit)
[4] NEWNYM + verification
[5] Monitor (repeat) — enter seconds
[6] Set SOCKS host:port (current: ${SOCKS_HOST}:${SOCKS_PORT})
[7] DNS leak test (DoH via Tor)
[8] Isolation hint
[A] Auto-fix ControlPort (edit torrc + restart)
[9] Help / usage
[0] Quit
${divider}
EOF
}

monitor_loop(){
  local secs="${1-10}"
  while true; do
    local ip4 ip6 c4 c6
    ip4="$(get_tor_ip_v 4)"; ip6="$(get_tor_ip_v 6)"
    c4="$(get_country "${ip4}")"; c6="$(get_country "${ip6}")"
    printf "[*] %s — Tor exit IPv4: %s (%s) | IPv6: %s (%s)\n" \
      "$(date -u +%FT%TZ)" "${ip4}" "${c4}" "${ip6}" "${c6}"
    sleep "${secs}"
  done
}

while true; do
  show_help
  read -rp "Choose: " choice
  case "$choice" in
    1) show_ips ;;
    2) verify_tor ;;
    3) send_newnym ;;
    4) send_newnym; verify_tor ;;
    5) read -rp "Interval seconds: " secs; monitor_loop "$secs" ;;
    6) read -rp "Enter SOCKS host: " SOCKS_HOST; read -rp "Enter SOCKS port: " SOCKS_PORT; ok "Updated SOCKS to ${SOCKS_HOST}:${SOCKS_PORT}" ;;
    7) dns_leak_test ;;
    8) isolation_hint ;;
    A|a) fix_controlport ;;
    9) show_help ;;
    0|q|Q) echo "Bye"; exit 0 ;;
    *) echo "[!] Invalid choice" ;;
  esac
done
