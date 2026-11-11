#!/usr/bin/env bash
# Set up the Raspberry Pi as a WPA2 AP (wlan1) with NAT to internet (wlan0/eth0).
# Run as root. Idempotent.
#
# Usage: sudo bash setup_ap.sh [start|stop|status]
#
# After this runs:
#   - Google Home Mini can join the AP and reach the internet
#   - All traffic is routed through this machine → tshark can capture it
#   - Run capture_ota.sh separately to record the OTA fetch

set -euo pipefail

AP_IFACE="${AP_IFACE:-wlan1}"        # interface that becomes the AP
WAN_IFACE="${WAN_IFACE:-wlan0}"      # interface with internet (or eth0)
AP_IP="10.42.0.1"
AP_SUBNET="10.42.0.0/24"
DHCP_RANGE="10.42.0.50,10.42.0.150,12h"
HOSTAPD_CONF="$(dirname "$0")/hostapd.conf"

cmd="${1:-start}"

stop_ap() {
    echo "[*] Stopping AP …"
    systemctl stop hostapd   2>/dev/null || true
    systemctl stop dnsmasq   2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$AP_SUBNET" -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || true
    ip addr flush dev "$AP_IFACE" 2>/dev/null || true
    echo 0 > /proc/sys/net/ipv4/ip_forward
    echo "[*] AP stopped"
}

start_ap() {
    echo "[*] Starting AP on $AP_IFACE (internet via $WAN_IFACE) …"

    # deps
    for pkg in hostapd dnsmasq iptables; do
        command -v $pkg >/dev/null || apt-get install -y $pkg
    done

    # bring up AP interface
    ip link set "$AP_IFACE" up
    ip addr flush dev "$AP_IFACE"
    ip addr add "$AP_IP/24" dev "$AP_IFACE"

    # NAT
    echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -t nat -C POSTROUTING -s "$AP_SUBNET" -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null \
        || iptables -t nat -A POSTROUTING -s "$AP_SUBNET" -o "$WAN_IFACE" -j MASQUERADE

    # dnsmasq DHCP
    systemctl stop dnsmasq 2>/dev/null || true
    dnsmasq \
        --interface="$AP_IFACE" \
        --dhcp-range="$DHCP_RANGE" \
        --dhcp-option=3,"$AP_IP" \
        --dhcp-option=6,"$AP_IP" \
        --no-hosts \
        --pid-file=/var/run/dnsmasq-ap.pid \
        --log-facility=/var/log/dnsmasq-ap.log &

    # hostapd
    systemctl stop hostapd 2>/dev/null || true
    hostapd -B -f /var/log/hostapd-ap.log "$HOSTAPD_CONF"

    echo "[+] AP up. SSID: $(grep ^ssid "$HOSTAPD_CONF" | cut -d= -f2)"
    echo "    Device IP will be in $AP_SUBNET"
    echo "    Run: bash capture_ota.sh   to start packet capture"
}

status_ap() {
    systemctl is-active hostapd 2>/dev/null && echo "hostapd: running" || echo "hostapd: stopped"
    systemctl is-active dnsmasq 2>/dev/null && echo "dnsmasq: running" || echo "dnsmasq: stopped"
    ip addr show "$AP_IFACE" 2>/dev/null | grep "inet "
}

case "$cmd" in
    start)  start_ap  ;;
    stop)   stop_ap   ;;
    status) status_ap ;;
    *)      echo "Usage: $0 [start|stop|status]"; exit 1 ;;
esac
