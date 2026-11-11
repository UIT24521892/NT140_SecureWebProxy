#!/usr/bin/env bash
# Validate a live change and roll back on error (TLS-3).
set -euo pipefail
mode=${1:-}
case "$mode" in splice|bump|selective) ;; *) echo 'invalid TLS mode' >&2; exit 2 ;; esac
previous=$(cat /run/nt140-tls-mode)
restore() {
  /usr/local/lib/nt140/prepare-tls.sh "$previous"
  squid -k reconfigure
}
trap restore ERR
/usr/local/lib/nt140/prepare-tls.sh "$mode"
output=$(squid -k parse 2>&1)
printf '%s\n' "$output"
if printf '%s\n' "$output" | grep -Eq 'FATAL|ERROR'; then false; fi
squid -k reconfigure
trap - ERR
