#!/usr/bin/env bash
# Change the active TLS mode transactionally, then persist .env (spec §6.2).
set -euo pipefail
cd "$(dirname "$0")/.."
mode=${1:-}
case "$mode" in splice|bump|selective) ;; *) echo 'usage: set-tls-mode.sh splice|bump|selective' >&2; exit 2 ;; esac

docker compose exec -T squid /usr/local/lib/nt140/switch-tls.sh "$mode"

# Atomic replacement also works with BSD tools and bash 3.2.
[ -f .env ] || cp .env.example .env
tmp=$(mktemp .env.tls.XXXXXX)
trap 'rm -f "$tmp"' EXIT
awk -v mode="$mode" 'BEGIN {found=0} /^TLS_MODE=/ {if (!found) print "TLS_MODE=" mode; found=1; next} {print} END {if (!found) print "TLS_MODE=" mode}' .env > "$tmp"
chmod 600 "$tmp"
mv "$tmp" .env
echo "TLS_MODE=$mode"
