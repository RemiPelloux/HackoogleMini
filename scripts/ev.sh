#!/usr/bin/env bash
# Run a rea command and save its JSON into evidence/: scripts/ev.sh <label> <rea args...>
set -euo pipefail
dir="$(cd "$(dirname "$0")/.." && pwd)"; . "$dir/scripts/rea-env.sh"
label="$1"; shift
out="$dir/evidence/$(date +%Y%m%d-%H%M%S)-$label.json"
rea "$@" --json > "$out"; echo "$out"
