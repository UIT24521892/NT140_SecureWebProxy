#!/usr/bin/env bash
# Run c-icap in the foreground (spec §7). Owner: THR-4.
set -euo pipefail

# PidFile and CommandsSocket of the packaged config live here; /run is empty at start.
mkdir -p /run/c-icap /var/log/c-icap
rm -f /run/c-icap/c-icap.pid /run/c-icap/c-icap.ctl
chown c-icap /run/c-icap /var/log/c-icap

# -N: stay in the foreground, -D: log to stdout so `docker compose logs icap` works.
exec c-icap -N -D -f /etc/c-icap/c-icap.conf
