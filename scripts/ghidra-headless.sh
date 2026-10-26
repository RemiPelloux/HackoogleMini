#!/usr/bin/env bash
# Direct Ghidra headless analysis of one ELF or raw ARM binary.
#
#   scripts/ghidra-headless.sh <binary> [base-address-hex]
#   scripts/ghidra-headless.sh target/cast_shell            # ELF: base from header
#   scripts/ghidra-headless.sh target/region.bin 0x8000     # raw: explicit base
#
# The Home Mini gen 1 SoC is a Marvell Armada 1500 Mini Plus (88DE3006):
# ARMv7 Cortex-A7, little-endian. Raw imports therefore default to ARM:LE:32:v7.
#
# Output:
#   work/ghidra-<name>/                       Ghidra project (open it in the GUI)
#   evidence/<ts>-ghidra-<name>.txt           headless log + decompiled C
set -uo pipefail
dir="$(cd "$(dirname "$0")/.." && pwd)"

bin="${1:-}"
base="${2:-}"
[ -n "$bin" ] || { echo "usage: $0 <binary> [base-address-hex]" >&2; exit 1; }
[ -f "$bin" ] || { echo "no such file: $bin" >&2; exit 1; }
bin="$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")"

GHIDRA="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
HEADLESS="$GHIDRA/support/analyzeHeadless"
[ -x "$HEADLESS" ] || { echo "Ghidra headless not found at $HEADLESS (set GHIDRA_INSTALL_DIR)" >&2; exit 1; }

mach="$(file -b "$bin")"
name="$(basename "$bin" | tr -c 'a-zA-Z0-9._-' '-')"
ts="$(date +%Y%m%d-%H%M%S)"
proj="$dir/work/ghidra-$name"
log="$dir/evidence/$ts-ghidra-$name.txt"
mkdir -p "$proj"

# ELF headers carry the correct processor; only raw blobs need to be told.
if [[ "$mach" == *ELF* ]]; then
  proc_args=()
  echo "[*] ELF detected, processor from header"
else
  if [ -z "$base" ]; then
    echo "[!] raw binary and no base address given -- assuming 0x8000." >&2
    echo "    Re-run with the real load address if disassembly looks wrong." >&2
    base=0x8000
  fi
  proc_args=(-processor "ARM:LE:32:v7")
  echo "[*] raw binary, importing ARM:LE:32:v7 at base $base"
fi

loader_args=()
if [ -n "$base" ]; then
  loader_args=(-loader BinaryLoader -loader-baseAddr "$base")
fi

"$HEADLESS" "$proj" "ghidra-$name" \
  -import "$bin" \
  "${proc_args[@]}" "${loader_args[@]}" \
  -scriptPath "$dir/scripts/ghidra" \
  -postScript DumpDecompiled.java \
  -analysisTimeoutPerFile 1800 \
  -overwrite 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}

echo
echo "log     : ${log#$dir/}   (exit $rc)"
echo "project : ${proj#$dir/}"
echo "GUI     : $GHIDRA/ghidraRun  then open project ${proj#$dir/}"
echo
echo "For REA queries against the same artifact instead of the project:"
echo "  source scripts/rea-env.sh"
echo "  rea analyze '$bin' --target-format raw-binary --architecture arm --entry-point ${base:-0x0} --json"
