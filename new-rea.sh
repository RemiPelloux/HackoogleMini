#!/usr/bin/env bash
# Create a new REA investigation folder from _template: ./new-rea.sh <name>
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
name="$*"; [ -n "$name" ] || { echo "usage: $0 <name>" >&2; exit 1; }
slug="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+|-+$//g')"
case "$slug" in ""|_template|rea) echo "invalid name: $name" >&2; exit 1 ;; esac
dest="$root/$slug"
[ -e "$dest" ] && { echo "already exists: $dest" >&2; exit 1; }
cp -a "$root/_template" "$dest"
grep -rlZ '{{NAME}}\|{{DATE}}' "$dest" | xargs -0 -r sed -i "s|{{NAME}}|$name|g; s|{{DATE}}|$(date +%F)|g"
echo "$dest"
