#!/usr/bin/env bash
# Portable host entry point (TLS-6, spec §10.4).
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 scripts/capture.py "$@"
