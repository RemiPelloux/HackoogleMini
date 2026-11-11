#!/usr/bin/env bash
# Easiest env: run the prebuilt STATIC PoC binaries inside a rootless bubblewrap
# sandbox. No Docker, no daemon, no root, no network, no Go at runtime.
# Filesystem is a throwaway tmpfs; the binaries carry all their deps.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sbx() { bwrap --unshare-all --die-with-parent --proc /proc --dev /dev --tmpfs /tmp \
              --ro-bind "$1" /poc /poc; }
command -v bwrap >/dev/null || { echo "need bubblewrap (bwrap); on Arch: pacman -S bubblewrap"; exit 1; }
[ -x "$here/bin/taildrive-poc" ] || { echo "binaries missing; run env/build.sh first"; exit 1; }
echo "===== [1/2] Taildrive WebDAV symlink escape (HIGH) — sandboxed ====="
sbx "$here/bin/taildrive-poc"
echo; echo "===== [2/2] Web login-mode request-gate (chain entry) — sandboxed ====="
sbx "$here/bin/webclient-gate-poc"
echo; echo "(ran under bwrap: no network, tmpfs root, rootless)"
