#!/usr/bin/env bash
# Generate the lab PKI into certs/ (spec §3). Idempotent; --force regenerates everything.
# Uses -extfile rather than -addext so it works with OpenSSL 3 and LibreSSL (macOS).
set -euo pipefail

cd "$(dirname "$0")/.."

OUT=certs
force=0
if [ "${1:-}" = "--force" ]; then force=1; fi

mkdir -p "$OUT"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ "$force" = 1 ]; then
  rm -f "$OUT"/*.crt "$OUT"/*.key "$OUT"/*.sha256
fi

serial() { echo "0x$(openssl rand -hex 16)"; }

public_ca_created=0

# make_ca NAME SUBJECT
make_ca() {
  local name=$1 subj=$2
  if [ -f "$OUT/$name.crt" ] && [ -f "$OUT/$name.key" ]; then
    echo "gen-certs: keep $name"
    return 1
  fi
  cat > "$tmp/$name.ext" <<'EOF'
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
  openssl genrsa -out "$OUT/$name.key" 2048 2>/dev/null
  openssl req -new -key "$OUT/$name.key" -subj "$subj" -out "$tmp/$name.csr"
  openssl x509 -req -in "$tmp/$name.csr" -signkey "$OUT/$name.key" -days 3650 -sha256 \
    -set_serial "$(serial)" -extfile "$tmp/$name.ext" -out "$OUT/$name.crt" 2>/dev/null
  chmod 600 "$OUT/$name.key"
  echo "gen-certs: created $name"
}

if make_ca lab-public-ca "/O=UIT NT140 Lab/CN=NT140 Lab Public Root CA"; then public_ca_created=1; fi
make_ca lab-proxy-ca "/O=UIT NT140 Lab/CN=NT140 SWG Proxy CA" || true

# testweb leaf, signed by the public CA. Re-issued whenever the CA is new.
if [ "$public_ca_created" = 1 ] || [ ! -f "$OUT/testweb.crt" ] || [ ! -f "$OUT/testweb.key" ]; then
  cat > "$tmp/testweb.ext" <<'EOF'
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:*.lab.test, DNS:lab.test
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
  openssl genrsa -out "$OUT/testweb.key" 2048 2>/dev/null
  openssl req -new -key "$OUT/testweb.key" -subj "/O=UIT NT140 Lab/CN=*.lab.test" -out "$tmp/testweb.csr"
  openssl x509 -req -in "$tmp/testweb.csr" -CA "$OUT/lab-public-ca.crt" -CAkey "$OUT/lab-public-ca.key" \
    -set_serial "$(serial)" -days 825 -sha256 -extfile "$tmp/testweb.ext" -out "$OUT/testweb.crt" 2>/dev/null
  chmod 600 "$OUT/testweb.key"
  rm -f "$OUT/pinned.sha256"
  echo "gen-certs: created testweb"
else
  echo "gen-certs: keep testweb"
fi

# SPKI pin of the testweb key for curl --pinnedpubkey (spec §3).
if [ ! -f "$OUT/pinned.sha256" ]; then
  pin=$(openssl x509 -in "$OUT/testweb.crt" -pubkey -noout \
    | openssl pkey -pubin -outform der \
    | openssl dgst -sha256 -binary \
    | openssl base64)
  echo "sha256//$pin" > "$OUT/pinned.sha256"
  echo "gen-certs: created pinned.sha256"
fi

openssl verify -CAfile "$OUT/lab-public-ca.crt" "$OUT/testweb.crt" >/dev/null
echo "gen-certs: testweb.crt verifies against lab-public-ca"
