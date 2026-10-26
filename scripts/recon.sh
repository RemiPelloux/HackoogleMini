#!/usr/bin/env bash
# Full recon pass: LAN cast devices + BLE Google devices. Writes evidence/ JSON.
#   scripts/recon.sh            -> everything
#   scripts/recon.sh --ble      -> BLE only
#   scripts/recon.sh --cast     -> cast only
set -uo pipefail
dir="$(cd "$(dirname "$0")/.." && pwd)"
py="$dir/.venv/bin/python"
ts="$(date +%Y%m%d-%H%M%S)"
mode="${1:---all}"
mkdir -p "$dir/evidence"

if [ ! -x "$py" ]; then
  echo "!! python venv missing. run: /usr/bin/python3 -m venv $dir/.venv && $dir/.venv/bin/pip install pychromecast bleak zeroconf" >&2
  exit 1
fi

if [ "$mode" != "--ble" ]; then
  echo "[cast] discovering + eureka_info dump..."
  "$py" "$dir/scripts/cast_scan.py" > "$dir/evidence/$ts-cast-scan.json" 2>"$dir/evidence/$ts-cast-scan.log"
  echo "  -> evidence/$ts-cast-scan.json"

  echo "[net] nmap sweep of local /24 for :8009 (cast) and :8008 (setup)..."
  subnet="$(ip -4 route | awk '/default/{print $3}' | head -1)"
  ip="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
  cidr="$(echo "$ip" | cut -d. -f1-3).0/24"
  nmap -p 8008,8009 --open -Pn --host-timeout 10s "$cidr" \
    > "$dir/evidence/$ts-nmap-cast.txt" 2>/dev/null
  echo "  -> evidence/$ts-nmap-cast.txt (subnet $cidr)"
fi

if [ "$mode" != "--cast" ]; then
  echo "[ble] scanning 20s for Google advertisers..."
  rfkill unblock bluetooth 2>/dev/null || true
  "$py" "$dir/scripts/ble_scan.py" > "$dir/evidence/$ts-ble-scan.json" 2>"$dir/evidence/$ts-ble-scan.log"
  echo "  -> evidence/$ts-ble-scan.json"
  bluetoothctl --timeout 20 scan on >/dev/null 2>&1
  for mac in $(grep -o '"address": *"[^"]*"' "$dir/evidence/$ts-ble-scan.json" | cut -d'"' -f4); do
    bluetoothctl info "$mac" >> "$dir/evidence/$ts-ble-info.txt" 2>&1
    echo "-----" >> "$dir/evidence/$ts-ble-info.txt"
  done
  echo "  -> evidence/$ts-ble-info.txt"
fi

echo "[done] $ts"
