#!/usr/bin/env bash
# Prepare PKI, helper DB and TLS config; also used for live mode changes (TLS-3).
set -euo pipefail

mode=${1:-${TLS_MODE:-selective}}
case "$mode" in splice|bump|selective) ;; *) echo 'TLS mode must be splice|bump|selective' >&2; exit 2 ;; esac
confd=/etc/squid/conf.d
templates=/etc/squid/templates
policy=/etc/squid/policy/lists
db=/var/lib/squid/ssl_db

install -d -o root -g proxy -m 0750 /etc/squid/ssl
for suffix in crt key; do
  source_file="/opt/certs/lab-proxy-ca.$suffix"
  [ -s "$source_file" ] || { echo "Missing $source_file; run make init" >&2; exit 1; }
  install -o root -g proxy -m 0640 "$source_file" "/etc/squid/ssl/lab-proxy-ca.$suffix"
done

# Initialize in a temporary child: the named-volume mount itself already exists.
fingerprint=$(openssl x509 -in /etc/squid/ssl/lab-proxy-ca.crt -noout -fingerprint -sha256)
if [ ! -s "$db/index.txt" ] && [ ! -f "$db/size" ]; then
  init_db=1
elif [ "$(cat "$db/.ca-fingerprint" 2>/dev/null || true)" != "$fingerprint" ]; then
  init_db=1
else
  init_db=0
fi
if [ "$init_db" = 1 ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  /usr/lib/squid/security_file_certgen -c -s "$tmp/db" -M 16MB
  mkdir -p "$db"
  cp -a "$tmp/db/." "$db/"
  printf '%s\n' "$fingerprint" > "$db/.ca-fingerprint"
fi
chown -R proxy:proxy "$db"

# POL-2 owns these ACLs. Bootstrap only missing declarations, using spec §5.1
# seeds until POL-2 is installed. Never override an existing policy declaration.
rm -f "$confd/19-tls-acl.conf"
declared() { grep -Eq "^[[:space:]]*acl[[:space:]]+$1[[:space:]]" "$confd"/*.conf; }
{
  echo '# Generated TLS compatibility declarations; POL-2 takes precedence.'
  for step in 1 2 3; do
    declared "step$step" || echo "acl step$step at_step SslBump$step"
  done
  if ! declared threat_sni; then
    sources=()
    for name in local/phishing local/malware feeds/phishing feeds/malware feeds/ut1_phishing feeds/ut1_malware; do
      [ ! -s "$policy/$name.txt" ] || sources+=("$policy/$name.txt")
    done
    if [ "${#sources[@]}" -gt 0 ]; then
      printf 'acl threat_sni ssl::server_name'
      printf ' "%s"' "${sources[@]}"
      printf '\n'
    else
      echo 'acl threat_sni ssl::server_name uitbank-secure-login.lab.test .malware-cdn.lab.test'
    fi
  fi
  if ! declared nobump_sni; then
    if [ -s "$policy/local/nobump.txt" ]; then
      echo 'acl nobump_sni ssl::server_name "/etc/squid/policy/lists/local/nobump.txt"'
    else
      echo 'acl nobump_sni ssl::server_name .uitbank.lab.test'
    fi
  fi
  declared mark_sni_threat || echo 'acl mark_sni_threat annotate_transaction policy=sni-threat'
} > "$confd/19-tls-acl.conf.tmp"
mv "$confd/19-tls-acl.conf.tmp" "$confd/19-tls-acl.conf"
cp "$templates/sslbump-common.conf.tmpl" "$confd/20-sslbump-common.inc"
cp "$templates/sslbump-$mode.conf.tmpl" "$confd/20-sslbump.conf"
# Squid may log the final spliced CONNECT without request headers. Preserve a
# parallel 16-field record plus client port so the runner can join the two phases.
format=$(sed -n 's/^logformat lab /logformat tls_trace /p' "$confd/60-logging.conf")
[ -n "$format" ] || { echo 'Missing lab logformat for TLS evidence' >&2; exit 1; }
printf '%s\t%%>p\n' "$format" > "$confd/21-tls-trace.conf"
echo 'access_log daemon:/var/log/squid/access_tls.log tls_trace' >> "$confd/21-tls-trace.conf"
printf '%s\n' "$mode" > /run/nt140-tls-mode
