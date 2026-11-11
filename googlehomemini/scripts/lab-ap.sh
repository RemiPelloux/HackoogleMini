#!/usr/bin/env bash
# Bring up a lab access point that owns the Home Mini's gateway.
#
# DESIGN: Single-radio mode. This iwlwifi card cannot run a concurrent AP vif
# alongside the managed uplink (the driver rejects the second vif with
# "class3 ... busy"). So this script DISCONNECTS the uplink and converts
# wlp0s20f3 itself into the AP. You lose internet while the lab AP is up.
# That is intentional and safe: NAT is off by default anyway, so the Mini
# cannot reach Google's OTA servers even if you had internet.
#
# To restore your normal connection afterwards:
#   sudo scripts/lab-ap.sh down
#   nmcli con up Livebox-C5C0
#
# Relationship to reconstruction/ap/: that is the clean-room design for a Pi
# with two radios (wlan1 as AP, wlan0 as uplink). This script is the
# single-radio laptop variant that actually works on this hardware.
#
# Requires: hostapd, dnsmasq, nft, tcpdump, iw, sudo.
#   sudo pacman -S hostapd dnsmasq   # (already installed)
#
# Usage:
#   sudo scripts/lab-ap.sh up      [--ssid gh-lab --pass ghlab12345] [--channel 6] [--nat]
#   sudo scripts/lab-ap.sh down
#   scripts/lab-ap.sh status
#
# NAT IS OFF BY DEFAULT, ON PURPOSE.
# Without --nat the Mini gets an IP, a DNS server and a gateway that goes nowhere:
# we still capture every hostname it asks for (the endpoint map we want), but it
# cannot download an OTA. That matters -- an auto-update may close the kernel bug
# we depend on, permanently. Only pass --nat once a NAND dump is banked, or when
# deliberately capturing an OTA fetch.
set -euo pipefail

dir="$(cd "$(dirname "$0")/.." && pwd)"
ev="$dir/evidence"
run="$dir/work/lab-ap"
saved_con="$run/saved-uplink-con"

ssid="gh-lab"
pass="ghlab12345"
iface="${IFACE:-wlp0s20f3}"
subnet="10.42.0"
channel_override=""
want_nat=0

action="${1:-status}"; shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --ssid)    shift; ssid="$1" ;;
    --pass)    shift; pass="$1" ;;
    --channel) shift; channel_override="$1" ;;
    --nat)     want_nat=1 ;;
  esac
  shift
done

need() { command -v "$1" >/dev/null || { echo "missing: $1"; exit 1; }; }

case "$action" in
up)
  [ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0 up"; exit 1; }
  for t in hostapd dnsmasq nft iw tcpdump nmcli; do need "$t"; done
  mkdir -p "$run"

  # Determine channel
  if [ -n "$channel_override" ]; then
    channel="$channel_override"
  else
    # Try to read current channel from the live link before we disconnect
    channel=$(iw dev "$iface" info 2>/dev/null | awk '/channel/{print $2}' || true)
    if [ -z "$channel" ]; then
      echo "!! $iface is not associated and no --channel given"; exit 2
    fi
  fi
  [ "$channel" -le 14 ] && band=2 || band=5
  hw=g; [ "$band" = 5 ] && hw=a
  echo "AP on $iface: channel=$channel band=${band}GHz hw_mode=$hw"

  # Save current connection so `down` can restore it
  cur_con=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null \
    | awk -F: -v d="$iface" '$2==d{print $1; exit}')
  if [ -n "$cur_con" ]; then
    echo "$cur_con" > "$saved_con"
    echo "saved uplink connection: $cur_con"
  else
    : > "$saved_con"
  fi

  # Clean slate
  pkill -F "$run/hostapd.pid" 2>/dev/null || true
  pkill -F "$run/dnsmasq.pid" 2>/dev/null || true
  [ -f "$run/tcpdump.pid" ] && kill "$(cat "$run/tcpdump.pid")" 2>/dev/null || true
  nft delete table ip ghlab 2>/dev/null || true

  # Disconnect managed mode and convert to AP
  nmcli dev disconnect "$iface" 2>/dev/null || true
  nmcli dev set "$iface" managed no
  ip link set "$iface" down
  iw dev "$iface" set type __ap
  actual_type=$(iw dev "$iface" info | awk '/type/{print $2}')
  [ "$actual_type" = "AP" ] || { echo "!! $iface refused AP mode (got $actual_type)"; exit 3; }
  ip addr flush dev "$iface"
  ip addr add "$subnet.1/24" dev "$iface"
  ip link set "$iface" up
  sleep 1

  cat >"$run/hostapd.conf" <<EOF
interface=$iface
driver=nl80211
ssid=$ssid
hw_mode=$hw
channel=$channel
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=$pass
rsn_pairwise=CCMP
auth_algs=1
ignore_broadcast_ssid=0
EOF
  hostapd -B -P "$run/hostapd.pid" -f "$run/hostapd.log" "$run/hostapd.conf"
  sleep 2
  ip link show "$iface" | grep -q UP || { echo "AP failed, see $run/hostapd.log"; tail -5 "$run/hostapd.log"; exit 3; }

  cat >"$run/dnsmasq.conf" <<EOF
interface=$iface
bind-interfaces
dhcp-range=$subnet.10,$subnet.100,255.255.255.0,12h
dhcp-option=3,$subnet.1
dhcp-option=6,$subnet.1
log-queries
log-dhcp
log-facility=$run/dnsmasq.log
no-resolv
server=1.1.1.1
server=8.8.8.8
EOF
  dnsmasq --conf-file="$run/dnsmasq.conf" --pid-file="$run/dnsmasq.pid"
  sleep 1

  # Forwarding policy — explicit DROP by default
  sysctl -qw net.ipv4.ip_forward=1
  nft add table ip ghlab
  nft add chain ip ghlab fwd '{ type filter hook forward priority 0 ; }'
  nft add chain ip ghlab post '{ type nat hook postrouting priority 100 ; }'
  if [ "$want_nat" -eq 1 ]; then
    nft add rule ip ghlab fwd iifname "$iface" accept
    nft add rule ip ghlab fwd oifname "$iface" ct state established,related accept
    nft add rule ip ghlab post oifname "$iface" masquerade
    nat_state="ENABLED -- the Mini can reach the internet and may auto-update"
  else
    nft add rule ip ghlab fwd iifname "$iface" log prefix "\"ghlab-drop \"" drop
    nft add rule ip ghlab fwd iifname "$iface" drop
    nat_state="BLOCKED (default) -- DNS is logged, no internet, no OTA"
  fi

  ts=$(date +%Y%m%d-%H%M%S)
  tcpdump -i "$iface" -n -s0 -w "$ev/$ts-lab-ap.pcap" 2>"$run/tcpdump.log" &
  echo $! >"$run/tcpdump.pid"

  cat <<EOF

lab AP up
  SSID      $ssid
  PSK       $pass
  channel   $channel (band ${band}GHz)
  interface $iface (single-radio mode — uplink disconnected)
  gateway   $subnet.1  (this machine)
  NAT       $nat_state
  DNS log   $run/dnsmasq.log      <- every hostname the Mini resolves
  DHCP log  $run/dnsmasq.log
  pcap      $ev/$ts-lab-ap.pcap
  hostapd   $run/hostapd.log

Next: point the Mini at this network with the setup API, then watch the DNS log:
  ./scripts/provision-wifi.py --ssid '$ssid' --pass '$pass'
  tail -f $run/dnsmasq.log

Restore internet:  sudo $0 down
EOF
  ;;

down)
  [ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0 down"; exit 1; }
  [ -f "$run/tcpdump.pid" ] && kill "$(cat "$run/tcpdump.pid")" 2>/dev/null || true
  [ -f "$run/dnsmasq.pid" ] && kill "$(cat "$run/dnsmasq.pid")" 2>/dev/null || true
  [ -f "$run/hostapd.pid" ] && kill "$(cat "$run/hostapd.pid")" 2>/dev/null || true
  nft delete table ip ghlab 2>/dev/null || true

  # Convert back to managed and reconnect
  ip link set "$iface" down 2>/dev/null || true
  iw dev "$iface" set type managed 2>/dev/null || true
  nmcli dev set "$iface" managed yes 2>/dev/null || true
  ip link set "$iface" up 2>/dev/null || true

  saved=""
  [ -f "$saved_con" ] && saved=$(cat "$saved_con")
  if [ -n "$saved" ]; then
    echo "restoring saved connection: $saved"
    nmcli con up "$saved" 2>/dev/null || echo "!! could not restore '$saved' — connect manually"
  else
    echo "no saved connection; connect manually: nmcli con up <name>"
  fi
  echo "lab AP down"
  ;;

status)
  echo "interface: $iface"
  iw dev "$iface" info 2>/dev/null | grep -E "type|channel|ssid" || echo "  (not available)"
  ip -br addr show "$iface" 2>/dev/null || echo "  (no address)"
  echo "hostapd: $(pgrep -F "$run/hostapd.pid" >/dev/null 2>&1 && echo running || echo stopped)"
  echo "dnsmasq: $(pgrep -F "$run/dnsmasq.pid" >/dev/null 2>&1 && echo running || echo stopped)"
  echo "clients:"
  ip neigh show dev "$iface" 2>/dev/null || true
  echo "dns queries (last 15):"
  tail -15 "$run/dnsmasq.log" 2>/dev/null || echo "  (none)"
  ;;

*)
  echo "usage: $0 {up|down|status}"; exit 1 ;;
esac