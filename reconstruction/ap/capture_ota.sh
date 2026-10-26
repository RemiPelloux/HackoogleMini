#!/usr/bin/env bash
# Capture all traffic from the Google Home Mini and analyse the OTA fetch.
#
# Usage:
#   sudo bash capture_ota.sh           # starts capture, Ctrl-C to stop
#   sudo bash capture_ota.sh --analyse evidence/ota-TIMESTAMP.pcapng
#
# What this does:
#   - Captures all packets from/to the Mini on the AP interface
#   - On stop, prints TLS SNI hostnames (reveals OTA endpoint even under TLS)
#   - Prints any plaintext HTTP URLs (there may be none)
#   - Prints device IP, model from DNS queries or HTTP Host headers
#   - Saves pcapng for Wireshark analysis

set -euo pipefail

AP_IFACE="${AP_IFACE:-wlan1}"
EVIDENCE_DIR="$(cd "$(dirname "$0")/../../evidence" && pwd)"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
PCAP="$EVIDENCE_DIR/${TIMESTAMP}-ota-capture.pcapng"

analyse() {
    local pcap="$1"
    echo ""
    echo "═══ TLS SNI hostnames (OTA endpoints visible even under TLS) ═══"
    tshark -r "$pcap" -Y 'tls.handshake.type == 1' \
           -T fields -e 'tls.handshake.extensions_server_name' 2>/dev/null \
        | sort -u | grep .

    echo ""
    echo "═══ HTTP Host headers ═══"
    tshark -r "$pcap" -Y 'http.request' \
           -T fields -e 'ip.src' -e 'http.host' -e 'http.request.uri' 2>/dev/null \
        | grep . || echo "(none — all HTTPS)"

    echo ""
    echo "═══ DNS queries (device name lookup pattern) ═══"
    tshark -r "$pcap" -Y 'dns.flags.response == 0' \
           -T fields -e 'ip.src' -e 'dns.qry.name' 2>/dev/null \
        | sort -u | grep .

    echo ""
    echo "═══ Devices on AP ═══"
    tshark -r "$pcap" -T fields -e 'ip.src' 2>/dev/null \
        | sort -u | grep -v '^10\.42\.0\.1$' | grep .

    echo ""
    echo "Full capture saved: $pcap"
    echo "Open in Wireshark for full analysis."
}

if [[ "${1:-}" == "--analyse" ]]; then
    analyse "$2"
    exit 0
fi

# Check deps
for cmd in tshark; do
    command -v $cmd >/dev/null || { echo "Install tshark: apt install tshark"; exit 1; }
done

echo "[*] Starting capture on $AP_IFACE → $PCAP"
echo "    Now provision the Mini via the Google Home app."
echo "    Ctrl-C to stop and analyse."
echo ""

tshark -i "$AP_IFACE" -w "$PCAP" &
TSHARK_PID=$!

cleanup() {
    echo ""
    echo "[*] Stopping capture (PID $TSHARK_PID) …"
    kill $TSHARK_PID 2>/dev/null || true
    wait $TSHARK_PID 2>/dev/null || true
    analyse "$PCAP"
}
trap cleanup INT TERM

wait $TSHARK_PID
