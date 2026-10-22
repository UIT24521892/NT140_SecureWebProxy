#!/bin/sh
# Prepare testweb content and the optional TLS listener before nginx starts (spec §8).
set -eu

mkdir -p /srv/data /etc/nginx/nt140

# Fixed random payloads, generated once per container start (never committed).
for size in 1 2 10; do
  [ -f "/srv/data/${size}m.bin" ] || head -c $((size * 1024 * 1024)) /dev/urandom > "/srv/data/${size}m.bin"
done
[ -f /srv/data/1m-nocache.bin ] || head -c 1048576 /dev/urandom > /srv/data/1m-nocache.bin

if [ -f /opt/certs/testweb.crt ] && [ -f /opt/certs/testweb.key ]; then
  cat > /etc/nginx/nt140/tls.conf <<'CONF'
listen 443 ssl default_server;
ssl_certificate /opt/certs/testweb.crt;
ssl_certificate_key /opt/certs/testweb.key;
CONF
  echo "40-nt140: TLS enabled on 443"
else
  : > /etc/nginx/nt140/tls.conf
  echo "40-nt140: certs/testweb.crt missing, HTTP only (run make init)"
fi
