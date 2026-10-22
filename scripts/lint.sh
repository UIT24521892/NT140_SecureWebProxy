#!/usr/bin/env bash
# Lint shell and Python sources (CLAUDE.md §5). Uses a local shellcheck if present,
# otherwise the pinned multi-arch image.
set -euo pipefail

cd "$(dirname "$0")/.."

SHELLCHECK_IMAGE="koalaman/shellcheck:v0.10.0"

sh_files=$(find scripts tests docker -type f -name '*.sh' 2>/dev/null | sort)
if [ -n "$sh_files" ]; then
  # shellcheck disable=SC2086  # word splitting of the file list is intended
  if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -x $sh_files
  else
    docker run --rm -v "$PWD:/mnt:ro" -w /mnt "$SHELLCHECK_IMAGE" -x $sh_files
  fi
  echo "lint: shellcheck ok ($(printf '%s\n' "$sh_files" | wc -l | tr -d ' ') files)"
fi

py_files=$(find scripts tests -type f -name '*.py' 2>/dev/null | sort)
if [ -n "$py_files" ]; then
  for f in $py_files; do
    python3 -c 'import ast, sys; ast.parse(open(sys.argv[1]).read(), sys.argv[1])' "$f"
  done
  echo "lint: python syntax ok ($(printf '%s\n' "$py_files" | wc -l | tr -d ' ') files)"
fi
