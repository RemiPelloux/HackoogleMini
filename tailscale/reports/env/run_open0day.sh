#!/usr/bin/env bash
# Run open0day's binary pipeline against the shipped tailscaled ELF.
# REQUIRES the Docker daemon running (sudo systemctl start docker) and will
# pull open0day/lifter + open0day/wsolver images on first run.
# NOTE: the `triage` step sends lifted-IR findings to an external LLM
# (codex-easy.ai per `open0day doctor`); drop it with `lift` + `analyze` if you
# want fully-local analysis.
set -euo pipefail
O=/home/tkmremi/Projects/pentest/tools/bin/open0day
BIN="${1:-/home/tkmremi/Desktop/work/REA/tailscale/target/tailscaled}"
OUT="${2:-/home/tkmremi/Desktop/work/REA/tailscale/evidence/open0day}"
mkdir -p "$OUT"
"$O" doctor
echo ">>> lifting + analyzing $BIN (this is heavy: 30MB Go ELF)"
"$O" pipeline "$BIN" --out "$OUT/tailscaled-pipeline.json" || {
  echo "pipeline failed (daemon/images?); see: open0day doctor"; exit 1; }
echo "done -> $OUT/tailscaled-pipeline.json"
