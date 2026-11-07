"""Parser for Squid's `lab` access log (spec §10.1). Owner: THR-3.

access_lab.log is TAB-separated with 16 fields, in the order of FIELDS.
Squid writes "-" for an empty field; parse_line() turns that into None.

Usage:
    from tests.lib import squidlog
    rec = squidlog.find_by_test_id("T1.2")          # waits up to 2 s (spec §11)
    print(squidlog.evidence(rec))                   # "TCP_DENIED/403 policy=social bump=-"

CLI (debugging):
    python3 -m tests.lib.squidlog [--log PATH] [TEST_ID]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Iterator

# Order must match `logformat lab` in docker/squid/conf/conf.d/60-logging.conf.
FIELDS = (
    "timestamp",   # 1  %{%Y-%m-%dT%H:%M:%S}tl.%03tu
    "duration_ms", # 2  %tr
    "client_ip",   # 3  %>a
    "user",        # 4  %un
    "result",      # 5  %Ss
    "status",      # 6  %>Hs
    "bytes",       # 7  %<st
    "method",      # 8  %rm
    "url",         # 9  %ru
    "sni",         # 10 %ssl::>sni
    "bump_mode",   # 11 %ssl::bump_mode
    "policy",      # 12 %{policy}note
    "mime",        # 13 %mt
    "adapt",       # 14 %adapt::sum_trs
    "test_id",     # 15 %{X-Lab-Test-Id}>h
    "hierarchy",   # 16 %Sh
)
INT_FIELDS = ("duration_ms", "status", "bytes")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG = Path(os.environ.get("LAB_ACCESS_LOG",
                                  REPO_ROOT / "logs" / "squid" / "access_lab.log"))


class LogFormatError(ValueError):
    """A line does not have the 16 fields of the `lab` format."""


def parse_line(line: str) -> dict:
    parts = line.rstrip("\r\n").split("\t")
    if len(parts) != len(FIELDS):
        raise LogFormatError(f"expected {len(FIELDS)} fields, got {len(parts)}: {line!r}")
    rec: dict = {}
    for name, raw in zip(FIELDS, parts):
        value = None if raw in ("", "-") else raw
        if name in INT_FIELDS and value is not None:
            try:
                value = int(value)
            except ValueError:
                pass
        rec[name] = value
    return rec


def iter_records(path: Path = DEFAULT_LOG, strict: bool = False) -> Iterator[dict]:
    """Yield parsed records. Malformed lines are skipped unless strict=True."""
    if not path.exists():
        return
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                yield parse_line(line)
            except LogFormatError:
                if strict:
                    raise


def records_for(test_id: str, path: Path = DEFAULT_LOG) -> list[dict]:
    return [r for r in iter_records(path) if r["test_id"] == test_id]


def find_by_test_id(test_id: str, path: Path = DEFAULT_LOG,
                    timeout: float = 2.0, interval: float = 0.2) -> dict | None:
    """Return the last log record for test_id, retrying up to `timeout` seconds
    because Squid's daemon logger writes asynchronously (spec §11)."""
    deadline = time.monotonic() + timeout
    while True:
        recs = records_for(test_id, path)
        if recs:
            return recs[-1]
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)


def evidence(rec: dict | None) -> str:
    """Evidence string for the results table: %Ss/%>Hs, policy, bump_mode."""
    if rec is None:
        return "no log line"
    return (f"{rec['result'] or '-'}/{rec['status'] if rec['status'] is not None else '-'}"
            f" policy={rec['policy'] or '-'} bump={rec['bump_mode'] or '-'}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Read Squid access_lab.log")
    ap.add_argument("test_id", nargs="?", help="print records for this X-Lab-Test-Id")
    ap.add_argument("--log", type=Path, default=DEFAULT_LOG)
    ap.add_argument("--check", action="store_true",
                    help="fail if any line does not have 16 fields")
    args = ap.parse_args(argv)

    if args.check:
        n = 0
        try:
            for n, _ in enumerate(iter_records(args.log, strict=True), 1):
                pass
        except LogFormatError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        print(f"OK: {n} lines, all with {len(FIELDS)} fields ({args.log})")
        return 0

    recs = records_for(args.test_id, args.log) if args.test_id else list(iter_records(args.log))
    for rec in recs:
        print(json.dumps(rec, ensure_ascii=False))
    if args.test_id and not recs:
        print(f"no line with test_id={args.test_id} in {args.log}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
