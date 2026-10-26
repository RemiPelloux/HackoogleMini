#!/usr/bin/env bash
# Bring up a lab access point that owns the Home Mini's gateway.
#
# Why: to learn what the device talks to (and to get at its OTA images) we need to
# be its router -- DHCP, DNS and the default gateway. This script puts the Mini on
# our own subnet with full DNS/query logging and a packet capture.
#
# Constraint that shapes the design: this Wi-Fi card allows AP + managed only on the
# SAME channel (`#channels <= 1`). So the uplink and the lab AP must share a channel.
# Livebox-C5C0 is on ch 6 (2.4 GHz), so make sure the laptop's uplink is that one:
#
#   nmcli con up Livebox-C5C0      # or pick the 2.4 GHz BSSID explicitly
#   ip -br addr show wlp0s20f3     # confirm you still have internet
#
# Relationship to reconstruction/ap/: that is the clean-room design for a Pi with two
# radios (wlan1 as AP, wlan0 as uplink). This script is the single-radio laptop variant
# that actually runs here, where AP and uplink must share one channel.
#
# Requires: hostapd, dnsmasq, nft, tcpdump, iw, sudo.
#   sudo apt install hostapd dnsmasq tcpdump iw
#
# Usage:
#   sudo scripts/lab-ap.sh up      [--ssid gh-lab --pass ghlab12345] [--channel 6] [--nat]
#   sudo scripts/lab-ap.sh down
#   scripts/lab-ap.sh status
#
# NAT IS OFF BY DEFAULT, ON PURPOSE.
# Without --nat the Mini gets an IP, a DNS server and a gateway that goes nowhere: we
# still capture every hostname it asks for (the endpoint map we want), but it cannot
# download an OTA. That matters -- an auto-update may close the kernel bug we depend
# on, permanently. Only pass --nat once a NAND dump is banked, or when deliberately
# capturing an OTA fetch.
set -euo pipefail
dir="$(cd "$(dirname "$0")/.." && pwd)"
ev="$dir/evidence"
run="$dir/work/lab-ap"
ssid="gh-lab"
pass="ghlab12345"
uplink="${UPLINK:-wlp0s20f3}"
apif="${APIF:-ghap}"
subnet="10.42.0"
channel_override=""
want_nat=0

action="${1:-status}"; shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --ssid) shift; ssid="$1" ;;
    --pass) shift; pass="$1" ;;
    --channel) shift; channel_override="$1" ;;
    --nat) want_nat=1 ;;
  esac
  shift
done

need() { command -v "$1" >/dev/null || { echo "missing: $1  (sudo apt install hostapd dnsmasq tcpdump iw)"; exit 1; }; }

case "$action" in
up)
  [ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0 up"; exit 1; }
  for t in hostapd dnsmasq nft iw tcpdump; do need "$t"; done
  mkdir -p "$run"

  chan="$(iw dev "$uplink" link 2>/dev/null | awk '/freq:/{print $2}')"
  if [ -n "$channel_override" ]; then
    channel="$channel_override"
    [ "$channel" -le 14 ] && band=2 || band=5
    echo "channel forced to $channel (band ${band}GHz)"
  else
    [ -n "$chan" ] || { echo "uplink $uplink is not associated -- pass --channel N, or connect Wi-Fi first"; exit 2; }
    if [ "$chan" -gt 5000 ]; then band=5; else band=2; fi
    channel=$(iw dev "$uplink" info 2>/dev/null | awk '/channel/{print $2}')
    echo "uplink=$uplink freq=${chan}MHz channel=${channel} band=${band}GHz"
  fi
  if [ "$band" = 2 ] && [ "$channel" -gt 14 ]; then
    echo "!! 2.4 GHz AP requested with channel $channel -- refusing"; exit 2
  fi

  # clean slate
  iw dev "$apif" del 2>/dev/null || true
  pkill -F "$run/hostapd.pid" 2>/dev/null || true
  pkill -F "$run/dnsmasq.pid" 2>/dev/null || true

  iw dev "$uplink" interface add "$apif" type __ap
  # Two traps here, both learned the hard way on iwlwifi:
  #  1. NetworkManager adopts a newly created vif and resets it to managed.
  #  2. `interface add ... type __ap` can still land as managed; re-assert AP mode.
  nmcli dev set "$apif" managed no 2>/dev/null || true
  iw dev "$apif" set type __ap
  [ "$(iw dev "$apif" info | awk '/type/{print $2}')" = "AP" ] || {
    echo "!! $apif refused AP mode (iwlwifi vif combination)"; exit 3; }
  ip addr flush dev "$apif"
  ip addr add "$subnet.1/24" dev "$apif"
  ip link set "$apif" up

  hw=g; [ "$band" = 5 ] && hw=a
  cat >"$run/hostapd.conf" <<EOF
interface=$apif
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
  ip link show "$apif" | grep -q UP || { echo "AP failed, see $run/hostapd.log"; tail -5 "$run/hostapd.log"; exit 3; }

  cat >"$run/dnsmasq.conf" <<EOF
interface=$apif
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

  # Forwarding policy. Default is an explicit DROP with logging, so that a stray
  # ip_forward=1 from something else can never leak the Mini onto the internet.
  sysctl -qw net.ipv4.ip_forward=1
  nft delete table ip ghlab 2>/dev/null || true
  nft add table ip ghlab
  nft add chain ip ghlab fwd '{ type filter hook forward priority 0 ; }'
  nft add chain ip ghlab post '{ type nat hook postrouting priority 100 ; }'
  if [ "$want_nat" -eq 1 ]; then
    nft add rule ip ghlab fwd iifname "$apif" oifname "$uplink" accept
    nft add rule ip ghlab fwd iifname "$uplink" oifname "$apif" ct state established,related accept
    nft add rule ip ghlab post oifname "$uplink" masquerade
    nat_state="ENABLED -- the Mini can reach the internet and may auto-update"
  else
    nft add rule ip ghlab fwd iifname "$apif" log prefix "\"ghlab-drop \"" drop
    nft add rule ip ghlab fwd iifname "$apif" drop
    nat_state="BLOCKED (default) -- DNS is logged, no internet, no OTA"
  fi

  ts=$(date +%Y%m%d-%H%M%S)
  tcpdump -i "$apif" -n -s0 -w "$ev/$ts-lab-ap.pcap" 2>"$run/tcpdump.log" &
  echo $! >"$run/tcpdump.pid"

  cat <<EOF

lab AP up
  SSID      $ssid
  PSK       $pass
  channel   $channel (band ${band}GHz)
  gateway   $subnet.1  (this machine)
  NAT       $nat_state
  DNS log   $run/dnsmasq.log      <- every hostname the Mini resolves
  DHCP log  $run/dnsmasq.log
  pcap      $ev/$ts-lab-ap.pcap
  hostapd   $run/hostapd.log

Next: point the Mini at this network with the setup API, then watch the DNS log:
  ./scripts/provision-wifi.py --ssid '$ssid' --pass '$pass'
  tail -f $run/dnsmasq.log

Tear down:  sudo $0 down
EOF
  ;;
down)
  [ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0 down"; exit 1; }
  [ -f "$run/tcpdump.pid" ] && kill "$(cat "$run/tcpdump.pid")" 2>/dev/null || true
  [ -f "$run/dnsmasq.pid" ] && kill "$(cat "$run/dnsmasq.pid")" 2>/dev/null || true
  [ -f "$run/hostapd.pid" ] && kill "$(cat "$run/hostapd.pid")" 2>/dev/null || true
  nft delete table ip ghlab 2>/dev/null || true
  iw dev "$apif" del 2>/dev/null || true
  echo "lab AP down"
  ;;
status)
  echo "interface: $apif"
  ip -br addr show "$apif" 2>/dev/null || echo "  (not up)"
  echo "clients:"
  ip neigh show dev "$apif" 2>/dev/null || true
  echo "dns queries (last 15):"
  tail -15 "$run/dnsmasq.log" 2>/dev/null || echo "  (none)"
  ;;
*)
  echo "usage: $0 {up|down|status}"; exit 1 ;;
esac
