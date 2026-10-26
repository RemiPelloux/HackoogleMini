#!/usr/bin/env bash
# Query every documented eureka_info param combination to extract cast_build_date
# and Chromium version from the device's setup API.
#
# Usage (while on the setup hotspot, or with --host if already on LAN):
#   bash scripts/get-build-info.sh
#   bash scripts/get-build-info.sh --host 10.42.0.100

set -euo pipefail
HOST="${1:-192.168.255.249}"
PORT="8443"
BASE="https://${HOST}:${PORT}"
CURL="curl -sk --max-time 10"

echo "=== Full build_info param ==="
$CURL "${BASE}/setup/eureka_info?params=build_info" | python3 -m json.tool

echo ""
echo "=== All documented params at once ==="
PARAMS="build_info,device_info,network_info,sign,opt_in,settings,version,uptime"
$CURL "${BASE}/setup/eureka_info?options=detail&params=${PARAMS}" | python3 -m json.tool

echo ""
echo "=== Port 8008 (HTTP, unencrypted, post-provisioning) ==="
curl -s --max-time 5 "http://${HOST}:8008/setup/eureka_info" | python3 -m json.tool 2>/dev/null || echo "(not available on this port)"

echo ""
echo "=== /setup/version (404 expected, but try) ==="
$CURL "${BASE}/setup/version" || true
