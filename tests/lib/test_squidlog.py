#!/usr/bin/env python3
"""Unit tests for tests/lib/squidlog.py (THR-3). Stdlib only, no lab needed.

    python3 tests/lib/test_squidlog.py        # from the repo root
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.lib import squidlog  # noqa: E402


def line(test_id: str, method: str = "GET", url: str = "http://allowed.lab.test/",
         result: str = "TCP_MISS", status: str = "200", ts: str = "2026-11-12T10:00:00.000",
         port: str | None = None) -> str:
    fields = [ts, "5", "10.10.0.101", "-", result, status, "1234", method, url,
              "-", "-", "-", "text/html", "-", test_id, "HIER_DIRECT"]
    assert len(fields) == len(squidlog.FIELDS)
    if port is not None:
        fields.append(port)
    return "\t".join(fields) + "\n"


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.lab = self.dir / "access_lab.log"
        self.tls = self.dir / "access_tls.log"
        self.lab.write_text("", encoding="utf-8")
        self.tls.write_text("", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def append(self, path: Path, text: str) -> None:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(text)


class DuplicatedHeader(Base):
    """Fix 1: -H plus --proxy-header on plain HTTP logs "T.X,%20T.X"."""

    def test_normalize(self) -> None:
        self.assertEqual(squidlog.normalize_test_id("T.X,%20T.X"), "T.X")
        self.assertEqual(squidlog.normalize_test_id("T.X, T.X"), "T.X")
        self.assertEqual(squidlog.normalize_test_id("T.X"), "T.X")
        self.assertIsNone(squidlog.normalize_test_id(None))

    def test_parse_line_normalizes(self) -> None:
        rec = squidlog.parse_line(line("T.HTTP,%20T.HTTP"))
        self.assertEqual(rec["test_id"], "T.HTTP")

    def test_found_by_plain_id(self) -> None:
        self.append(self.lab, line("T.HTTP,%20T.HTTP"))
        self.append(self.lab, line("T.CONNECT", method="CONNECT", url="allowed.lab.test:443"))
        rec = squidlog.find_by_test_id("T.HTTP", self.lab, timeout=0)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["method"], "GET")
        self.assertEqual(squidlog.find_by_test_id("T.CONNECT", self.lab, timeout=0)["method"],
                         "CONNECT")

    def test_run_id_prefix_kept(self) -> None:
        tid = "20261112-100000.T1.2"
        self.append(self.lab, line(f"{tid},%20{tid}"))
        self.assertEqual(len(squidlog.records_for(tid, self.lab)), 1)


class StaleLines(Base):
    """Fix 2: an older line with the same id must not be returned after mark()."""

    def test_old_line_ignored_after_mark(self) -> None:
        self.append(self.lab, line("T1.2", ts="2026-11-01T08:00:00.000", status="403",
                                   result="TCP_DENIED"))
        start = squidlog.mark(self.lab, self.tls)
        self.assertIsNotNone(squidlog.find_by_test_id("T1.2", self.lab, timeout=0))
        self.assertIsNone(squidlog.find_by_test_id("T1.2", self.lab, timeout=0.3,
                                                   since=start.lab))
        self.assertIsNone(squidlog.best_record("T1.2", timeout=0.3, since=start,
                                               lab_path=self.lab, tls_path=self.tls))

    def test_new_line_found_after_mark(self) -> None:
        self.append(self.lab, line("T1.2", ts="2026-11-01T08:00:00.000"))
        start = squidlog.mark(self.lab, self.tls)
        self.append(self.lab, line("T1.2", ts="2026-11-12T10:00:00.000", status="403",
                                   result="TCP_DENIED"))
        rec = squidlog.find_by_test_id("T1.2", self.lab, timeout=0, since=start.lab)
        self.assertEqual(rec["timestamp"], "2026-11-12T10:00:00.000")
        self.assertEqual(len(squidlog.records_for("T1.2", self.lab, since=start.lab)), 1)

    def test_repeat_two_probes_same_id(self) -> None:
        first = squidlog.mark(self.lab, self.tls)
        self.append(self.lab, line("T10.1", result="TCP_MISS"))
        second = squidlog.mark(self.lab, self.tls)
        self.append(self.lab, line("T10.1", result="TCP_MEM_HIT"))
        self.assertEqual(len(squidlog.records_for("T10.1", self.lab, since=first.lab)), 2)
        self.assertEqual(squidlog.records_for("T10.1", self.lab, since=second.lab)[0]["result"],
                         "TCP_MEM_HIT")

    def test_truncated_log_read_from_start(self) -> None:
        self.append(self.lab, line("OLD") * 3)
        start = squidlog.mark(self.lab, self.tls)
        self.lab.write_text(line("T1.2"), encoding="utf-8")  # recreated, now smaller
        self.assertIsNotNone(squidlog.find_by_test_id("T1.2", self.lab, timeout=0,
                                                      since=start.lab))

    def test_partial_last_line_skipped(self) -> None:
        self.append(self.lab, line("T1.2").rstrip("\n"))
        self.assertEqual(squidlog.records_for("T1.2", self.lab), [])
        self.append(self.lab, "\n")
        self.assertEqual(len(squidlog.records_for("T1.2", self.lab)), 1)

    def test_connection_records_since(self) -> None:
        self.append(self.tls, line("T7.5", method="CONNECT", result="NONE_NONE",
                                   url="allowed.lab.test:443", port="40000"))
        self.append(self.tls, line("-", method="CONNECT", result="TCP_TUNNEL",
                                   url="allowed.lab.test:443", port="40000"))
        start = squidlog.mark(self.lab, self.tls)
        self.assertEqual(len(squidlog.connection_records("T7.5", self.tls)), 2)
        self.assertEqual(squidlog.connection_records("T7.5", self.tls, since=start.tls), [])


class Format(Base):
    def test_wrong_field_count(self) -> None:
        with self.assertRaises(squidlog.LogFormatError):
            squidlog.parse_line("a\tb\n")

    def test_empty_fields_are_none(self) -> None:
        rec = squidlog.parse_line(line("T1"))
        self.assertIsNone(rec["sni"])
        self.assertEqual(rec["status"], 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
