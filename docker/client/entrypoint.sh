#!/usr/bin/env bash
# Install lab CAs according to MANAGED, export proxy settings, then run CMD (spec §3, §9).
set -euo pipefail

install_ca() {
  if [ -f "/opt/certs/$1.crt" ]; then
    cp "/opt/certs/$1.crt" "/usr/local/share/ca-certificates/nt140-$1.crt"
    echo "client: trusting $1"
  else
    echo "client: /opt/certs/$1.crt missing (run make init)" >&2
  fi
}

install_ca lab-public-ca
if [ "${MANAGED:-0}" = "1" ]; then
  install_ca lab-proxy-ca
fi
update-ca-certificates >/dev/null

# Convenience for manual demos; tests pass -x explicitly (spec §9.1).
if [ -n "${PROXY_URL:-}" ]; then
  printf 'export http_proxy=%s https_proxy=%s\n' "$PROXY_URL" "$PROXY_URL" > /etc/profile.d/nt140-proxy.sh
fi

exec "$@"
