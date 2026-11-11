#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Container layout: /pocs/{taildrive,webclient}. Local layout: resolve from repo.
if [ -d /pocs/taildrive ]; then
  TD=/pocs/taildrive; WC=/pocs/webclient
else
  TD="$here/../taildrive-symlink-escape/poc"; WC="$here/../webclient-rebind-control-repoint/poc"
fi
echo "############################################################"
echo "# Tailscale v1.104.1 — vulnerability PoC environment"
echo "# go: $(go version)"
echo "############################################################"
echo; echo "===== [1/2] Taildrive WebDAV symlink escape  (HIGH) ====="
( cd "$TD" && go run . )
echo; echo "===== [2/2] Web login-mode request-gate (rebinding chain entry) ====="
( cd "$WC" && go run . )
echo; echo "Full writeups: reports/*/report.md ; repro: webclient-rebind-control-repoint/poc/repro.md"
