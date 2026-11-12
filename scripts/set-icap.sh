#!/usr/bin/env bash
# Switch ICAP behaviour at runtime and persist it in .env (spec §7, §13.1). Owner: THR-4.
#   set-icap.sh on|off        ICAP_BYPASS: on = fail-open, off = fail-closed (default)
#   set-icap.sh --enabled 0|1 ICAP_ENABLED: 0 = skip scanning (benchmarks only)
# Portable: bash 3.2/BSD (macOS) and bash 5/GNU (Linux).
set -euo pipefail

cd "$(dirname "$0")/.."

usage() { echo 'usage: set-icap.sh on|off | --enabled 0|1' >&2; exit 2; }

env_get() {
  local value=''
  [ ! -f .env ] || value=$(grep -E "^$1=" .env | tail -n 1 | cut -d= -f2- || true)
  if [ -n "$value" ]; then printf '%s\n' "$value"; else printf '%s\n' "$2"; fi
}

env_set() {
  local tmp
  [ -f .env ] || cp .env.example .env
  tmp=$(mktemp .env.icap.XXXXXX)
  awk -v key="$1" -v value="$2" '
    BEGIN { found = 0 }
    index($0, key "=") == 1 { if (!found) print key "=" value; found = 1; next }
    { print }
    END { if (!found) print key "=" value }' .env > "$tmp"
  mv "$tmp" .env
}

bypass=$(env_get ICAP_BYPASS off)
enabled=$(env_get ICAP_ENABLED 1)
case "${1:-}" in
  on|off) [ "$#" -eq 1 ] || usage; bypass=$1 ;;
  --enabled) [ "$#" -eq 2 ] || usage; enabled=$2 ;;
  *) usage ;;
esac
case "$bypass" in on) flag=1 ;; off) flag=0 ;; *) usage ;; esac
case "$enabled" in 1) access=allow ;; 0) access=deny ;; *) usage ;; esac

# Render like the entrypoint does, validate, and only then reload. On a parse
# error the previous file is put back so squid keeps a working configuration.
# shellcheck disable=SC2016  # expanded by sh inside the container, not here
docker compose exec -T -e ICAP_BYPASS_FLAG="$flag" -e ICAP_ACCESS="$access" squid sh -euc '
  conf=/etc/squid/conf.d/30-icap.conf
  cp "$conf" "$conf.bak"
  envsubst "\${ICAP_BYPASS_FLAG} \${ICAP_ACCESS}" < /etc/squid/templates/icap.conf.tmpl > "$conf"
  if out=$(squid -k parse 2>&1) && ! printf "%s\n" "$out" | grep -Eq "FATAL|ERROR"; then
    rm -f "$conf.bak"
    squid -k reconfigure 2>/dev/null
  else
    mv "$conf.bak" "$conf"
    printf "%s\n" "$out" | grep -E "FATAL|ERROR" >&2
    exit 1
  fi'

env_set ICAP_BYPASS "$bypass"
env_set ICAP_ENABLED "$enabled"
echo "ICAP_BYPASS=$bypass ICAP_ENABLED=$enabled"
