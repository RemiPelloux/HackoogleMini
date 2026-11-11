#!/usr/bin/env bash
# Recreate the Python venv used by the recon scripts.
set -euo pipefail
dir="$(cd "$(dirname "$0")/.." && pwd)"
/usr/bin/python3 -m venv "$dir/.venv"
"$dir/.venv/bin/pip" install --upgrade pip >/dev/null
"$dir/.venv/bin/pip" install -r "$dir/requirements.txt"
echo "venv ready: $dir/.venv"
