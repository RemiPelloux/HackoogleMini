#!/usr/bin/env bash
# REA firmware pipeline for a Google Home Mini image.
#
#   scripts/fw-analyze.sh target/<image>.bin
#
# Produces, in order, into evidence/ (never touching target/):
#   1. host-side identification (file, size, sha256, entropy, binwalk, markers)
#   2. rea inspect-firmware-regions   -> partition / filesystem candidates
#   3. rea extract-firmware           -> carved regions with provenance
#   4. rea analyze                    -> per-extracted-binary overview
#   5. rea decompile-all              -> pseudocode dump for the largest ELF
#
# The Home Mini gen 1 SoC is a Marvell Armada 1500 Mini Plus (88DE3006):
# ARMv7 Cortex-A7, little-endian -> --architecture arm for raw regions.
set -uo pipefail
dir="$(cd "$(dirname "$0")/.." && pwd)"
. "$dir/scripts/rea-env.sh"

img="${1:-}"
[ -n "$img" ] || { echo "usage: $0 target/<firmware-image>" >&2; exit 1; }
[ -f "$img" ] || { echo "no such file: $img" >&2; exit 1; }
img="$(cd "$(dirname "$img")" && pwd)/$(basename "$img")"

ts="$(date +%Y%m%d-%H%M%S)"
out="$dir/evidence/fw-$ts"
work="$dir/work/fw-$ts"
mkdir -p "$out" "$work"
# Both ghidra and ida can open a native target, so REA needs an explicit choice.
# Ghidra is the always-available default; override with REA_PROVIDER=ida.
PROVIDER="${REA_PROVIDER:-ghidra}"
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "1/5 host identification"
{
  echo "## file";   file "$img"
  echo; echo "## size";   stat -c '%s bytes' "$img"
  echo; echo "## sha256"; sha256sum "$img"
  echo; echo "## entropy per 1 MiB (compressed/encrypted regions read ~8.0)"
  python3 - "$img" <<'PY'
import math, sys
data = open(sys.argv[1], 'rb').read()
step = 1 << 20
for i in range(0, min(len(data), 64 << 20), step):
    blk = data[i:i+step]
    if not blk:
        break
    c = [0]*256
    for b in blk:
        c[b] += 1
    n = len(blk)
    ent = -sum((x/n)*math.log2(x/n) for x in c if x)
    print(f"  {i:#010x}  {ent:5.2f} bits/byte")
PY
  echo; echo "## binwalk"
  binwalk "$img" 2>/dev/null | head -60
  echo; echo "## markers"
  strings -a -t x "$img" \
    | grep -iE "u-boot|Linux version|squashfs|jffs2|cramfs|armada|88de3|marvell|cast_shell|tot|bruno" \
    | head -40
} > "$out/01-host-ident.txt" 2>&1
echo "  -> ${out#$dir/}/01-host-ident.txt"

say "2/5 rea inspect-firmware-regions"
rea inspect-firmware-regions "$img" --json > "$out/02-regions.json" 2>"$out/02-regions.err"
echo "  -> ${out#$dir/}/02-regions.json ($(wc -c <"$out/02-regions.json") B)"

say "3/5 rea extract-firmware"
# extract-firmware takes the output directory POSITIONALLY and it must not exist yet.
rea extract-firmware "$img" "$work/extracted" --json \
  > "$out/03-extract.json" 2>"$out/03-extract.err"
echo "  -> ${out#$dir/}/03-extract.json"
echo "  -> ${work#$dir/}/extracted ($(find "$work/extracted" -type f 2>/dev/null | wc -l) files)"

say "4/5 rea analyze (extracted ELF regions, provider: $PROVIDER)"
i=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  case "$(file -b "$f")" in
    *ELF*) ;;
    *) continue ;;
  esac
  i=$((i + 1))
  if rea analyze "$f" --provider "$PROVIDER" --json > "$out/04-analyze-$i.json" 2>/dev/null; then
    echo "  analyzed: ${f#$work/}"
  else
    echo "  skipped : ${f#$work/} (see 04-analyze-$i.json)"
  fi
done < <(find "$work/extracted" -type f 2>/dev/null | head -40)
[ "$i" -gt 0 ] || echo "  (no ELF regions; inspect 02-regions.json and carve manually)"

say "5/5 decompile-all on the largest ELF"
big=""
bigsize=0
while IFS= read -r f; do
  case "$(file -b "$f")" in *ELF*) ;; *) continue ;; esac
  sz=$(stat -c%s "$f")
  if [ "$sz" -gt "$bigsize" ]; then big="$f"; bigsize=$sz; fi
done < <(find "$work/extracted" -type f 2>/dev/null)
if [ -n "$big" ]; then
  echo "  target: ${big#$work/} ($bigsize B)"
  rea decompile-all "$big" --provider "$PROVIDER" --output "$work/pseudo" --json \
    > "$out/05-decompile-all.json" 2>"$out/05-decompile-all.err"
  n=$(find "$work/pseudo" -type f 2>/dev/null | wc -l)
  echo "  -> ${work#$dir/}/pseudo ($n files)"
  [ "$n" -gt 0 ] || echo "  (see 05-decompile-all.err; raw regions need scripts/ghidra-headless.sh with a base address)"
else
  echo "  (no ELF extracted; run scripts/ghidra-headless.sh on a carved region with its load address)"
fi

say "done"
echo "evidence: ${out#$dir/}"
echo "workdir : ${work#$dir/}"
cat <<'EOF'

Next, map the pieces that decide the whole project:
  * the Cast receiver (cast_shell / libcast) and its mDNS + :8009 TLS layer
  * the Assistant client -- the cloud STT/agent path, i.e. the thing to replace
  * updater + signature verification -- decides whether custom firmware is possible at all
EOF
