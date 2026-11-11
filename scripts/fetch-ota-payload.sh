#!/usr/bin/env bash
# Download the real Google-signed OTA payload.bin for this device and extract
# the rootfs so we can pull cast_shell for offline Ghidra analysis.
#
# PREREQUISITE: device must be on the Pi lab AP (scripts/lab-ap.sh start).
# HOW IT WORKS:
#   1. The device POSTs an OTA check-in to the update server on first boot.
#      We capture this via tshark on the AP interface.
#   2. The check-in response contains a signed payload_url (Google CDN).
#   3. We download payload.bin (the real, Google-signed delta) from that URL.
#   4. We use delta_generator (from Chrome OS update_engine) to extract the
#      partition images from the payload.
#   5. unsquashfs extracts the SquashFS rootfs.
#   6. cast_shell lands at target/rootfs/system/chrome/cast_shell.
#
# ALTERNATIVE (if no tshark): point update server DNS at Pi, run a proxy
# that logs the check-in JSON and then forwards to Google. See below.
#
# Usage:
#   # Terminal 1 (run first):
#   bash scripts/fetch-ota-payload.sh --capture
#
#   # Terminal 2 (provision the device):
#   python3 scripts/provision-wifi.py --ssid gh-lab --pass ghlab12345
#
#   # After OTA URL is captured, extract:
#   bash scripts/fetch-ota-payload.sh --extract /path/to/payload.bin

set -euo pipefail

AP_IFACE="${AP_IFACE:-wlan1}"
OUT_DIR="$(cd "$(dirname "$0")/.." && pwd)/target"
EVIDENCE_DIR="$(cd "$(dirname "$0")/.." && pwd)/evidence"
PAYLOAD_BIN="${OUT_DIR}/payload.bin"

mkdir -p "$OUT_DIR" "$EVIDENCE_DIR"

case "${1:-}" in
# ── Capture mode: intercept OTA check-in ───────────────────────────────────
--capture)
  echo "[*] Capturing OTA check-in on ${AP_IFACE}..."
  echo "[*] Provision the device now (python3 scripts/provision-wifi.py ...)"
  echo "[*] Ctrl-C to stop capture."
  echo ""

  # Log file for tshark
  PCAP="${EVIDENCE_DIR}/ota-capture-$(date +%Y%m%d-%H%M%S).pcap"

  # Capture, watching for the OTA check-in POST and the CDN redirect/payload URL
  tshark -i "${AP_IFACE}" \
    -f "tcp port 443 or tcp port 80" \
    -w "${PCAP}" &
  TSHARK_PID=$!

  # Also run an HTTP proxy/logger on port 8080 to catch plaintext OTA check-in
  python3 - << 'PYEOF' &
import http.server, json, sys, datetime, os

EVIDENCE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        '..', 'evidence')

class OTAProxy(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        out = os.path.join(EVIDENCE, f'ota-checkin-{ts}.bin')
        with open(out, 'wb') as f:
            f.write(body)
        print(f'\n[OTA PROXY] {self.command} {self.path}')
        print(f'  Body ({len(body)}B) saved to {out}')
        try:
            print('  JSON:', json.loads(body)['request'][0] if b'request' in body else '(binary)')
        except Exception:
            pass
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a): pass

with http.server.HTTPServer(('', 8082), OTAProxy) as srv:
    print('[*] OTA check-in proxy on :8082')
    srv.serve_forever()
PYEOF
  PROXY_PID=$!

  trap "kill $TSHARK_PID $PROXY_PID 2>/dev/null; echo '[*] Stopped'; exit" INT TERM

  # Watch tshark output for OTA-related SNI / hostnames
  tshark -i "${AP_IFACE}" -Y 'ssl.handshake.type == 1 or http.request' \
    -T fields -e ip.src -e ssl.handshake.extensions_server_name -e http.host \
    -e http.request.uri 2>/dev/null | grep -E "gstatic|gvt1|googleapis|dl.google|update" &

  wait
  ;;

# ── Extract mode: unpack payload.bin → rootfs ───────────────────────────────
--extract)
  PAYLOAD="${2:-$PAYLOAD_BIN}"
  if [[ ! -f "$PAYLOAD" ]]; then
    echo "[!] payload.bin not found at: $PAYLOAD"
    echo "    Provide path: $0 --extract /path/to/payload.bin"
    exit 1
  fi

  echo "[*] Payload: $PAYLOAD ($(du -sh "$PAYLOAD" | cut -f1))"
  echo ""

  # Method 1: delta_generator (Chrome OS update_engine tool)
  DELTA_GEN=$(command -v delta_generator 2>/dev/null \
    || command -v /usr/bin/delta_generator 2>/dev/null \
    || find /opt /usr/local -name delta_generator 2>/dev/null | head -1 || true)

  if [[ -n "$DELTA_GEN" ]]; then
    echo "[*] Using delta_generator..."
    "$DELTA_GEN" --in_file="$PAYLOAD" \
      --out_file="${OUT_DIR}/rootfs.img" \
      --partition_name=rootfs 2>&1 | tail -20
  else
    echo "[!] delta_generator not found. Install with:"
    echo "    pip install payload-dumper-go  # or build from:"
    echo "    https://github.com/ssut/payload-dumper-go"
    echo ""
    # Try payload-dumper-go
    if command -v payload-dumper-go &>/dev/null; then
      echo "[*] Using payload-dumper-go..."
      payload-dumper-go -output "$OUT_DIR" "$PAYLOAD"
    else
      echo "[*] Trying python payload_dumper..."
      python3 - "$PAYLOAD" "$OUT_DIR" << 'PYEOF'
import sys, os, struct, hashlib

# Minimal OTA payload.bin parser for Cast/Eureka (Chrome OS update_engine format)
# Header: "CrAU" magic + version + manifest_size + metadata_sig_size + manifest protobuf
MAGIC = b"CrAU"

def parse(path, outdir):
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            print(f"[!] Not a Chrome OS OTA payload (magic={magic})")
            sys.exit(1)
        version = struct.unpack(">Q", f.read(8))[0]
        mf_size = struct.unpack(">Q", f.read(8))[0]
        sig_size = struct.unpack(">I", f.read(4))[0] if version >= 2 else 0
        mf_data = f.read(mf_size)
        f.read(sig_size)   # skip metadata signature
        data_offset = f.tell()
        print(f"[*] Payload version {version}, manifest {mf_size}B, data starts at {data_offset:#x}")

        # Try to import the protobuf parser
        try:
            sys.path.insert(0, os.path.dirname(__file__))
            from update_metadata_pb2 import DeltaArchiveManifest
            mf = DeltaArchiveManifest()
            mf.ParseFromString(mf_data)
            for part in mf.partitions:
                name = part.partition_name
                print(f"  partition: {name}")
                out = os.path.join(outdir, f"{name}.img")
                with open(out, "wb") as g:
                    for op in part.operations:
                        f.seek(data_offset + op.data_offset)
                        g.write(f.read(op.data_length))
                print(f"    → {out}")
        except ImportError:
            print("[!] protobuf parser not available; saving raw data section")
            out = os.path.join(outdir, "payload_data.bin")
            with open(out, "wb") as g:
                while True:
                    chunk = f.read(65536)
                    if not chunk: break
                    g.write(chunk)
            print(f"[*] Raw data saved to {out}")

parse(sys.argv[1], sys.argv[2])
PYEOF
    fi
  fi

  # Attempt to unsquashfs the rootfs image
  ROOTFS_IMG=$(ls "${OUT_DIR}"/rootfs.img "${OUT_DIR}"/system.img 2>/dev/null | head -1 || true)
  if [[ -n "$ROOTFS_IMG" ]]; then
    echo ""
    echo "[*] Extracting SquashFS from ${ROOTFS_IMG}..."
    ROOTFS_DIR="${OUT_DIR}/rootfs"
    unsquashfs -d "$ROOTFS_DIR" "$ROOTFS_IMG" 2>&1 | tail -5
    echo ""
    if [[ -f "${ROOTFS_DIR}/system/chrome/cast_shell" ]]; then
      echo "[+] cast_shell found at: ${ROOTFS_DIR}/system/chrome/cast_shell"
      echo "[+] SHA256: $(sha256sum "${ROOTFS_DIR}/system/chrome/cast_shell")"
      file "${ROOTFS_DIR}/system/chrome/cast_shell"
      ls -lh "${ROOTFS_DIR}/system/chrome/cast_shell"
      echo ""
      echo "[*] Next: load in REA/Ghidra for analysis"
      echo "    rea open target/rootfs/system/chrome/cast_shell --provider ghidra"
    else
      echo "[!] cast_shell not found at expected path. Listing /system/chrome/:"
      ls "${ROOTFS_DIR}/system/chrome/" 2>/dev/null || echo "(path not found)"
    fi
  fi
  ;;

# ── DNS redirect mode: intercept OTA check-in transparently ─────────────────
--dns-intercept)
  echo "[*] Setting up DNS redirect for OTA update servers..."
  echo "    Requires dnsmasq running on the AP interface."

  # Add OTA server entries to dnsmasq — point at our proxy
  PI_IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
  OTA_HOSTS=(
    "oobe.gvt1.com"
    "redirector.gvt1.com"
    "dl.google.com"
    "clients2.google.com"
    "www.gstatic.com"
  )
  DNSMASQ_CONF="/etc/dnsmasq.d/ota-intercept.conf"
  {
    for h in "${OTA_HOSTS[@]}"; do
      echo "address=/${h}/${PI_IP}"
    done
  } | sudo tee "$DNSMASQ_CONF"
  sudo systemctl restart dnsmasq

  echo "[*] OTA DNS redirected to ${PI_IP}"
  echo "[*] Start the proxy: bash $0 --capture (it listens on :8082)"
  echo "[*] Provision the device and watch the proxy log for the payload_url"
  echo "[*] To undo: sudo rm $DNSMASQ_CONF && sudo systemctl restart dnsmasq"
  ;;

*)
  echo "Usage:"
  echo "  $0 --capture              # capture OTA check-in (run before provisioning)"
  echo "  $0 --dns-intercept        # redirect OTA DNS to this Pi"
  echo "  $0 --extract payload.bin  # extract rootfs from downloaded payload"
  exit 1
  ;;
esac
