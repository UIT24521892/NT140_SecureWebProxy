"""Parser for Squid's `lab` access log (spec §10.1). Owner: THR-3.

access_lab.log is TAB-separated with 16 fields, in the order of FIELDS.
Squid writes "-" for an empty field; parse_line() turns that into None.

Import: the repo root must be on sys.path. tests/run_all.py does this itself
(`sys.path.insert(0, REPO_ROOT)` then `from tests.lib import squidlog`); from a
shell, run Python from the repo root.

    from tests.lib import squidlog
    start = squidlog.mark()                          # log sizes before the probe
    ... run the probe ...
    rec = squidlog.best_record("T1.2", since=start)  # waits up to 2 s (spec §11)
    print(squidlog.evidence(rec))                    # "TCP_DENIED/403 policy=social bump=-"

`since` limits the search to lines written after mark(): test ids are reused
across runs and access_lab.log is kept (logfile_rotate 0), so without it an
old line with the same id can be returned.

CLI (debugging, from the repo root):
    python3 -m tests.lib.squidlog [--log PATH] [--since BYTES] [TEST_ID]

Unit tests: python3 tests/lib/test_squidlog.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import re
import time
from dataclasses import dataclass
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


# For plain HTTP a client that sends the id both with -H and --proxy-header
# (spec §9.1) makes Squid log the merged value "T.X,%20T.X" (or "T.X, T.X").
_ID_SEPARATOR = re.compile(r",(?:%20|\s)*")


def normalize_test_id(raw: str | None) -> str | None:
    """First value of a possibly repeated X-Lab-Test-Id header."""
    if raw is None:
        return None
    first = _ID_SEPARATOR.split(raw, maxsplit=1)[0].strip()
    return first or None


@dataclass(frozen=True)
class LogMark:
    """Byte offsets of access_lab.log and access_tls.log at one moment."""
    lab: int = 0
    tls: int = 0


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def _lines(path: Path, since: int = 0) -> Iterator[str]:
    """Complete lines of path starting at byte offset `since`.

    If the file is now smaller than `since` it was truncated or recreated, so
    reading starts again from 0. A last line without a newline is still being
    written by Squid's daemon logger and is left for the next read.
    """
    if not path.exists():
        return
    with path.open("rb") as fh:
        if since > _size(path):
            since = 0
        fh.seek(since)
        for raw in fh:
            if not raw.endswith(b"\n"):
                return
            yield raw.decode("utf-8", errors="replace")


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
    rec["test_id"] = normalize_test_id(rec["test_id"])
    return rec


def iter_records(path: Path = DEFAULT_LOG, strict: bool = False,
                 since: int = 0) -> Iterator[dict]:
    """Yield parsed records written at or after byte offset `since`.
    Malformed lines are skipped unless strict=True."""
    for line in _lines(path, since):
        if not line.strip():
            continue
        try:
            yield parse_line(line)
        except LogFormatError:
            if strict:
                raise


def records_for(test_id: str, path: Path = DEFAULT_LOG, since: int = 0) -> list[dict]:
    test_id = normalize_test_id(test_id) or test_id
    return [r for r in iter_records(path, since=since) if r["test_id"] == test_id]


def find_by_test_id(test_id: str, path: Path = DEFAULT_LOG,
                    timeout: float = 2.0, interval: float = 0.2,
                    since: int = 0) -> dict | None:
    """Return the last log record for test_id written after `since`, retrying up
    to `timeout` seconds because Squid's daemon logger writes asynchronously (spec §11)."""
    deadline = time.monotonic() + timeout
    while True:
        recs = records_for(test_id, path, since)
        if recs:
            return recs[-1]
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)


# Written by docker/squid/prepare-tls.sh: the `lab` fields plus the client port.
TLS_TRACE = DEFAULT_LOG.parent / "access_tls.log"


def mark(lab_path: Path = DEFAULT_LOG, tls_path: Path | None = None) -> LogMark:
    """Current log sizes; pass as `since` to ignore lines written before now."""
    return LogMark(_size(lab_path), _size(tls_path or TLS_TRACE))


def connection_records(test_id: str, path: Path | None = None,
                       since: int = 0) -> list[dict]:
    """Records on the same client connection as the request carrying test_id.

    For a spliced or terminated CONNECT, Squid logs the request headers on a
    NONE_NONE line and the final TCP_TUNNEL line without them (docs/verify-log.md).
    access_tls.log adds the client port, which lets the two lines be joined.
    """
    path = path or TLS_TRACE
    test_id = normalize_test_id(test_id) or test_id
    parsed: list[tuple[dict, str]] = []
    for line in _lines(path, since):
        parts = line.rstrip("\r\n").split("\t")
        if len(parts) == len(FIELDS) + 1:
            parsed.append((parse_line("\t".join(parts[:-1])), parts[-1]))
    anchors = [i for i, (rec, _) in enumerate(parsed) if rec["test_id"] == test_id]
    if not anchors:
        return []
    start = anchors[-1]
    conn = (parsed[start][0]["client_ip"], parsed[start][1])
    return [rec for rec, port in parsed[start:] if (rec["client_ip"], port) == conn]


def all_records(test_id: str, since: LogMark | None = None,
                lab_path: Path | None = None, tls_path: Path | None = None) -> list[dict]:
    """Lines tagged with test_id plus the untagged lines of the same connection,
    written after `since` (both logs)."""
    since = since or LogMark()
    tid = normalize_test_id(test_id) or test_id
    tagged = records_for(tid, lab_path or DEFAULT_LOG, since.lab)
    return tagged + [r for r in connection_records(tid, tls_path, since.tls)
                     if r["test_id"] != tid]


def best_record(test_id: str, timeout: float = 2.0, interval: float = 0.2,
                since: LogMark | None = None,
                lab_path: Path | None = None, tls_path: Path | None = None) -> dict | None:
    """Last completed record for test_id (not NONE_NONE if one exists), with retry."""
    deadline = time.monotonic() + timeout
    while True:
        recs = all_records(test_id, since, lab_path, tls_path)
        done = [r for r in recs if r["result"] != "NONE_NONE"]
        if done:
            return done[-1]
        if time.monotonic() >= deadline:
            return recs[-1] if recs else None
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
    ap.add_argument("--since", type=int, default=0, metavar="BYTES",
                    help="only read lines written after this byte offset")
    ap.add_argument("--check", action="store_true",
                    help="fail if any line does not have 16 fields")
    args = ap.parse_args(argv)

    if args.check:
        n = 0
        try:
            for n, _ in enumerate(iter_records(args.log, strict=True, since=args.since), 1):
                pass
        except LogFormatError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1
        print(f"OK: {n} lines, all with {len(FIELDS)} fields ({args.log})")
        return 0

    recs = (records_for(args.test_id, args.log, args.since) if args.test_id
            else list(iter_records(args.log, since=args.since)))
    for rec in recs:
        print(json.dumps(rec, ensure_ascii=False))
    if args.test_id and not recs:
        print(f"no line with test_id={args.test_id} in {args.log}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
