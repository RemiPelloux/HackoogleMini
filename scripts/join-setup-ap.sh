#!/usr/bin/env bash
# Join the Home Mini's open setup access point, talk to its local setup API, and
# always restore the previous Wi-Fi connection.
#
# Why: an unprovisioned Home device exposes the same setup server the Google Home
# app uses -- over TLS on :8443 (https_setup_supported) and eureka_info on :8008.
# This gets the FULL device_info (the BLE characteristics cap it at 512 bytes) and
# is the prerequisite for provisioning the device onto our own network, which in
# turn is what lets us observe its cloud/OTA traffic.
#
# This drops the machine off its normal network for the duration. The previous
# connection is restored on exit, including on error or Ctrl-C.
#
# Usage: scripts/join-setup-ap.sh [--keep] [--ssid <ssid>] [--api]
#   --keep   leave the setup AP connection active (for manual poking)
#   --api    enumerate the setup API surface (GET only) before restoring
set -uo pipefail
dir="$(cd "$(dirname "$0")/.." && pwd)"
ev="$dir/evidence"
mkdir -p "$ev"
ts="$(date +%Y%m%d-%H%M%S)"
log="$ev/$ts-setup-ap.txt"
KEEP=0
API=0
SSID=""
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) KEEP=1 ;;
    --api) API=1 ;;
    --ssid) shift; SSID="$1" ;;
  esac
  shift
done

say() { printf '\n== %s\n' "$*" | tee -a "$log"; }

PROFILE="gh-setup-$$"
PREV="$(nmcli -t -f NAME,TYPE con show --active | awk -F: '$2=="802-11-wireless"{print $1; exit}')"
say "previous Wi-Fi connection: ${PREV:-<none>}"

restore() {
  if [ "$KEEP" -eq 0 ]; then
    nmcli con down "$PROFILE" >/dev/null 2>&1
    nmcli con delete "$PROFILE" >/dev/null 2>&1
    [ -n "$PREV" ] && nmcli con up "$PREV" >/dev/null 2>&1 && say "restored: $PREV"
  else
    say "--keep: left on $PROFILE (delete later with: nmcli con delete $PROFILE)"
  fi
}
trap restore EXIT INT TERM

# ---- find the setup AP if the caller did not name one -------------------------
if [ -z "$SSID" ]; then
  say "scanning for a Google setup AP"
  nmcli dev wifi rescan >/dev/null 2>&1
  sleep 6
  # the Mini advertises an OPEN AP whose BSSID equals its hotspot_bssid
  SSID="$(nmcli -t -f SSID,SECURITY dev wifi list 2>/dev/null \
          | awk -F: '$2=="" || $2=="--" {print $1}' \
          | grep -iE '^(googlehome|chromecast|nest)' | head -1)"
fi
if [ -z "$SSID" ]; then
  say "no open Google setup AP found -- is the Mini powered and unprovisioned?"
  exit 2
fi
say "setup AP SSID: '$SSID'"

# ---- join --------------------------------------------------------------------
nmcli con delete "$PROFILE" >/dev/null 2>&1
nmcli con add type wifi con-name "$PROFILE" ssid "$SSID" autoconnect no >>"$log" 2>&1
nmcli con modify "$PROFILE" 802-11-wireless.hidden yes \
  ipv4.method auto ipv6.method ignore >>"$log" 2>&1
say "joining ..."
if ! nmcli con up "$PROFILE" >>"$log" 2>&1; then
  say "join failed (see $log)"
  exit 3
fi

# wait for an address
ip=""
for _ in $(seq 1 20); do
  ip="$(ip -4 -o addr show scope global | awk '{print $4}' | grep -v '^100\.' | head -1)"
  [ -n "$ip" ] && break
  sleep 1
done
[ -n "$ip" ] || { say "no IPv4 address obtained"; exit 4; }

myip="${ip%/*}"
gw="$(ip route | awk '/default/{print $3; exit}')"
say "our address: $myip   gateway: ${gw:-<none>}"

# ---- probe the setup server --------------------------------------------------
cands="$gw 192.168.255.1 192.168.255.249 192.168.44.1 8.8.8.8"
say "probing candidate setup hosts on :8443 (https) and :8008 (eureka_info)"
for h in $cands; do
  [ -n "$h" ] || continue
  for port in 8443 8008; do
    scheme=https; [ "$port" = 8008 ] && scheme=http
    code="$(timeout 4 curl -sk -o /dev/null -w '%{http_code}' \
            "$scheme://$h:$port/setup/eureka_info?options=detail" 2>/dev/null)"
    echo "   $scheme://$h:$port  -> ${code:-no-response}" | tee -a "$log"
  done
done

# ---- dump the full device info ----------------------------------------------
say "fetching full eureka_info from every host that answered"
for h in $cands; do
  [ -n "$h" ] || continue
  for port in 8443 8008; do
    scheme=https; [ "$port" = 8008 ] && scheme=http
    out="$ev/$ts-eureka-$h-$port.json"
    if timeout 12 curl -sk "$scheme://$h:$port/setup/eureka_info?options=detail" \
        -o "$out" 2>/dev/null && [ -s "$out" ]; then
      if head -c 1 "$out" | grep -q '{'; then
        echo "   saved $out ($(stat -c%s "$out") B)" | tee -a "$log"
        python3 - "$out" <<'PY' 2>/dev/null | tee -a "$log"
import json, sys
d = json.load(open(sys.argv[1]))
def pick(o, keys, pre=""):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in keys and not isinstance(v, (dict, list)):
                print(f"   {pre}{k} = {v}")
            pick(v, keys, pre + k + ".")
pick(d, {"model_name","product_name","cast_build_revision","mac_address","ssid",
         "device_id","uma_client_id","version","build_version","release_track",
         "firmware_version","name","time_format","timezone","locale",
         "secure_setup_enforcement_supported","https_setup_supported",
         "hotspot_bssid","public_key","country_code","setup_state"})
PY
      else
        rm -f "$out"
      fi
    fi
  done
done

# ---- optionally enumerate the full setup API surface -------------------------
if [ "$API" -eq 1 ]; then
  host="$(ip route | awk '/default/{print $3; exit}')"
  say "enumerating setup API on $host (GET only, read-only)"
  python3 "$dir/scripts/setup_api.py" --host "$host" --port 8443 \
    --out "$ev/$ts-setup-api.json" 2>&1 | tee -a "$log"
fi

say "done -- evidence prefix: evidence/$ts-*"
