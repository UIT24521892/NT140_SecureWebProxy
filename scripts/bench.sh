#!/usr/bin/env bash
# Portable host entry point (TLS-7, spec §13.1).
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/bench.py "$@"
