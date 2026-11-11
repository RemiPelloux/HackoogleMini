#!/usr/bin/env bash
# Rebuild the static PoC binaries. Needs Go >=1.27 (mise go@1.27.3 auto-used).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MISE_GO="$HOME/.local/share/mise/installs/go/1.27.3/bin"; [ -d "$MISE_GO" ] && export PATH="$MISE_GO:$PATH"
export GOTOOLCHAIN=local GOFLAGS=-mod=mod CGO_ENABLED=0
mkdir -p "$here/bin"
( cd "$here/../taildrive-symlink-escape/poc" && go build -ldflags='-s -w' -o "$here/bin/taildrive-poc" . )
( cd "$here/../webclient-rebind-control-repoint/poc" && go build -ldflags='-s -w' -o "$here/bin/webclient-gate-poc" . )
echo "built: $here/bin/{taildrive-poc,webclient-gate-poc}"
