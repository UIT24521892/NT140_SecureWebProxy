#!/usr/bin/env bash
# Build squid's error directory at image build time (spec §5.6). Owner: POL-3.
# Output = every stock template + one ERR_LAB_<REASON> page per line of reasons.tsv.
set -euo pipefail

src=${1:?source dir with ERR_LAB.tmpl and reasons.tsv}
out=${2:?output error directory}

mkdir -p "$out"
cp /usr/share/squid/errors/templates/* "$out/"
while IFS=$'\t' read -r reason vi en; do
  [ -n "$reason" ] || continue
  name=ERR_LAB_$(printf '%s' "$reason" | tr 'a-z-' 'A-Z_')
  sed -e "s|@REASON@|$reason|g" -e "s|@VI@|$vi|g" -e "s|@EN@|$en|g" "$src/ERR_LAB.tmpl" > "$out/$name"
done < "$src/reasons.tsv"
