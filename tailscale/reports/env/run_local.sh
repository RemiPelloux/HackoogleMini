#!/usr/bin/env bash
# No-Docker runner: uses the mise-managed Go (or PATH go) to run both PoCs now.
set -euo pipefail
MISE_GO="$HOME/.local/share/mise/installs/go/1.27.3/bin"
[ -d "$MISE_GO" ] && export PATH="$MISE_GO:$PATH"
export GOTOOLCHAIN=local GOFLAGS=-mod=mod
exec "$(dirname "$0")/run_all.sh"
