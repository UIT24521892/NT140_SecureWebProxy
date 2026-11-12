"""Write results.csv / results.md and the results/latest symlink (spec §11). Owner: THR-2."""
from __future__ import annotations

import csv
import os
import platform
from collections import Counter
from pathlib import Path

from .model import FAIL, PASS, PASS_LIMITATION, SKIP, Result

COLUMNS = ("ID", "Scenario", "Actor", "URL", "State", "Expected", "Observed", "Status", "Evidence")


def _state_text(state: dict) -> str:
    return " ".join(f"{k}={str(v).lower() if isinstance(v, bool) else v}"
                    for k, v in sorted(state.items())) or "-"


def row(result: Result, run_id: str = "") -> dict[str, str]:
    case = result.case
    target = (case.url or "").replace("{runid}", run_id) or " ".join(case.command) or case.list_file or case.source or ""
    if case.kind == "sni_probe":
        target = f"CONNECT {case.host}:443 sni={case.sni}"
    return {
        "ID": case.id, "Scenario": case.scenario,
        "Actor": case.actor or case.service or "-", "URL": target,
        "State": _state_text(result.state), "Expected": case.expected_text,
        "Observed": result.observed, "Status": result.status, "Evidence": result.evidence,
    }


def summary(results: list[Result]) -> str:
    count = Counter(r.status for r in results)
    text = (f"{len(results)} cases: {count[PASS]} PASS, {count[PASS_LIMITATION]} PASS (limitation), "
            f"{count[FAIL]} FAIL, {count[SKIP]} SKIP")
    p0_skipped = [r.case.id for r in results if r.status == SKIP and r.case.priority == "P0"]
    if p0_skipped:
        text += f". P0 skipped (not accepted yet): {', '.join(p0_skipped)}"
    return text


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|") or "-"


def write(results: list[Result], out_dir: Path, run_id: str, argv: list[str]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = [row(r, run_id) for r in results]
    with (out_dir / "results.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    lines = [
        "# Test results", "",
        f"- Run: `{run_id}`", f"- Arch: `{platform.machine()}`",
        f"- Command: `{' '.join(argv)}`", f"- Summary: {summary(results)}", "",
        "| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS),
    ]
    lines += ["| " + " | ".join(_cell(r[c]) for c in COLUMNS) + " |" for r in rows]
    md = out_dir / "results.md"
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    latest = out_dir.parent / "latest"
    if latest.is_symlink() or latest.exists():
        latest.unlink()
    os.symlink(out_dir.name, latest)
    return md
