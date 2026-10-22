#!/usr/bin/env bash
# Render runtime config, prepare state, validate and run squid in the foreground (spec §15).
set -euo pipefail

log() { echo "entrypoint: $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

TLS_MODE=${TLS_MODE:-selective}
ICAP_BYPASS=${ICAP_BYPASS:-off}
ICAP_ENABLED=${ICAP_ENABLED:-1}
GUEST_RATE_BYTES=${GUEST_RATE_BYTES:-262144}

case "$TLS_MODE" in splice|bump|selective) ;; *) die "TLS_MODE must be splice|bump|selective, got '$TLS_MODE'" ;; esac
case "$ICAP_BYPASS" in
  off) ICAP_BYPASS_FLAG=0 ;;
  on) ICAP_BYPASS_FLAG=1 ;;
  *) die "ICAP_BYPASS must be on|off, got '$ICAP_BYPASS'" ;;
esac
export TLS_MODE ICAP_BYPASS_FLAG ICAP_ENABLED GUEST_RATE_BYTES

POLICY=/etc/squid/policy
TEMPLATES=/etc/squid/templates
CONFD=/etc/squid/conf.d

# ./policy is mounted read-only; generated files come from `make init` (spec §5.5).
[ -f "$POLICY/generated/work_hours.conf" ] || die "missing $POLICY/generated/work_hours.conf, run 'make init' on the host"

# Lab public CA: lets squid verify testweb when bumping (spec §3).
if [ -f /opt/certs/lab-public-ca.crt ]; then
  cp /opt/certs/lab-public-ca.crt /usr/local/share/ca-certificates/nt140-lab-public-ca.crt
  update-ca-certificates >/dev/null
fi

# Render templates with an explicit variable whitelist: squid does not read env vars (spec §15).
render() {
  local src=$1 dst=$2
  # shellcheck disable=SC2016  # the literal ${VAR} list is what envsubst expects
  envsubst '${TLS_MODE} ${ICAP_BYPASS_FLAG} ${ICAP_ENABLED} ${GUEST_RATE_BYTES}' < "$src" > "$dst"
  log "rendered $(basename "$dst") from $(basename "$src")"
}

sslbump_tmpl="$TEMPLATES/sslbump-$TLS_MODE.conf.tmpl"
if [ ! -f "$sslbump_tmpl" ]; then
  log "no template for TLS_MODE=$TLS_MODE yet (TLS-3), using placeholder"
  sslbump_tmpl="$TEMPLATES/sslbump-placeholder.conf.tmpl"
fi
render "$sslbump_tmpl" "$CONFD/20-sslbump.conf"

if [ -f "$TEMPLATES/icap.conf.tmpl" ]; then
  render "$TEMPLATES/icap.conf.tmpl" "$CONFD/30-icap.conf"
else
  rm -f "$CONFD/30-icap.conf"
fi

if [ -f "$TEMPLATES/delay.conf.tmpl" ]; then
  render "$TEMPLATES/delay.conf.tmpl" "$CONFD/51-delay.conf"
else
  rm -f "$CONFD/51-delay.conf"
fi

mkdir -p /var/log/squid /var/spool/squid /var/lib/squid
chown -R proxy:proxy /var/log/squid /var/spool/squid /var/lib/squid

# Create cache_dir structure on first start (no-op without cache_dir).
squid -z --foreground -f /etc/squid/squid.conf 2>&1 | sed 's/^/squid -z: /' >&2

if ! parse_out=$(squid -k parse -f /etc/squid/squid.conf 2>&1); then
  printf '%s\n' "$parse_out" >&2
  die "squid -k parse failed"
fi
if printf '%s\n' "$parse_out" | grep -qE 'FATAL|ERROR'; then
  printf '%s\n' "$parse_out" | grep -E 'FATAL|ERROR|WARNING' >&2
  die "squid -k parse reported errors"
fi
log "squid -k parse ok"

rm -f /run/squid.pid
exec squid -N -d 1 -f /etc/squid/squid.conf
