#!/usr/bin/env bash
# One request, one JSON result; verbose curl output stays private (spec §9.1).
set -euo pipefail

usage() {
  echo 'usage: probe.sh [-u user:pass] [-t ID] [--cacert FILE] [--pinned] [--dryrun] [--direct] [--max-time N] URL' >&2
  exit 2
}

credential='' test_id='' cacert='' url='' pinned=0 dryrun=0 direct=0 max_time=30
while [ "$#" -gt 0 ]; do
  case "$1" in
    -u|-t|--cacert|--max-time)
      [ "$#" -ge 2 ] || usage
      case "$1" in
        -u) credential=$2 ;; -t) test_id=$2 ;; --cacert) cacert=$2 ;; --max-time) max_time=$2 ;;
      esac
      shift 2 ;;
    --pinned) pinned=1; shift ;;
    --dryrun) dryrun=1; shift ;;
    --direct) direct=1; shift ;;
    -*) usage ;;
    *) [ -z "$url" ] || usage; url=$1; shift ;;
  esac
done
case "$url" in http://*|https://*) ;; *) usage ;; esac
case "$test_id" in *$'\r'*|*$'\n'*) usage ;; esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/empty-ca"
args=(--disable --silent --show-error --verbose --connect-timeout 5 --max-time "$max_time"
      --output "$tmp/body" --dump-header "$tmp/headers" --write-out '%{json}'
      -H "X-Lab-Test-Id: $test_id")
# HTTP sends -H to the proxy already. Adding --proxy-header there duplicates it.
# HTTPS needs a separate header on CONNECT as well as on the inner request.
case "$url" in https://*) args+=(--proxy-header "X-Lab-Test-Id: $test_id") ;; esac
if [ "$direct" = 1 ]; then
  args+=(--noproxy '*')
else
  : "${PROXY_URL:?PROXY_URL must be set for a proxied request}"
  args+=(--proxy "$PROXY_URL" --noproxy '')
fi
[ -z "$credential" ] || args+=(--proxy-user "$credential")
# Override both trust locations: --cacert alone may still use the system capath.
[ -z "$cacert" ] || args+=(--cacert "$cacert" --capath "$tmp/empty-ca")
if [ "$pinned" = 1 ]; then
  args+=(--pinnedpubkey "$(cat /opt/certs/pinned.sha256)")
fi
[ "$dryrun" = 0 ] || args+=(-H 'X-Lab-Dryrun: 1')
curl_exit=0
curl "${args[@]}" --url "$url" > "$tmp/metrics" 2> "$tmp/verbose" || curl_exit=$?
python3 "$(dirname "$0")/probe_result.py" "$tmp" "$curl_exit" "$test_id" "$url"
