#!/usr/bin/env bash
# Download an OTA zip offered by Omaha (see scripts/omaha_spoof.py), verify it against
# the offer's sha256, and unpack it next to the zip in target/ota-<build>/ (gitignored):
#   zip/      the OTA zip contents (system.img, boot.img, bootloaders, tz, META-INF)
#   rootfs/   system.img (SquashFS) unpacked -> chrome/cast_shell, bin/, lib/ ...
#   kernel.bin, Image (decompressed), ramdisk/ (from boot.img, incl. dmtable)
#
# Usage: scripts/fetch-ota.sh <codebase-url> <sha256> <build>
set -euo pipefail
url="$1"; sha="$2"; build="$3"
root="$(cd "$(dirname "$0")/.." && pwd)"
w="$root/target/ota-$build"
mkdir -p "$w"
zip="$w/$(basename "${url%%\?*}")"
[ -f "$zip" ] || curl -fSL -o "$zip" "$url"
echo "$sha  $zip" | sha256sum -c -

rm -rf "$w/zip" "$w/rootfs" "$w/ramdisk" "$w/kernel.bin" "$w/Image" "$w/ramdisk.xz"
unzip -q "$zip" -d "$w/zip"
7z x -y -o"$w/rootfs" "$w/zip/system.img" >/dev/null   # unsquashfs works too

python3 -I - "$w" <<'EOF'
import lzma, re, struct, sys
w = sys.argv[1]
b = open(f"{w}/zip/boot.img", "rb").read()
o = b.find(b"ANDROID!")              # boot.img starts with a signature header
ks, _, rs, _, _, _, _, ps = struct.unpack_from("<8I", b, o + 8)
k = b[o + ps:o + ps + ks]
open(f"{w}/kernel.bin", "wb").write(k)
open(f"{w}/ramdisk.xz", "wb").write(b[o + ps + -(-ks // ps) * ps:][:rs])
print("signed header bytes:", o, "cmdline:", b[o + 64:o + 576].split(b"\0")[0].decode())
i = k.find(b"\xfd7zXZ\x00")
if i >= 0:
    img = lzma.LZMADecompressor().decompress(k[i:])
    open(f"{w}/Image", "wb").write(img)
    print(re.search(rb"Linux version [^\n]+", img).group().decode())
EOF
mkdir -p "$w/ramdisk" && (cd "$w/ramdisk" && xz -dc ../ramdisk.xz | cpio -idm --quiet) && rm "$w/ramdisk.xz"
cat "$w/zip/META-INF/com/android/metadata"
echo "unpacked to $w"
