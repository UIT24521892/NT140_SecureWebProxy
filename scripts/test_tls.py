#!/usr/bin/env python3
"""Run TV2 scenarios while THR-2 is pending; never change acceptance expectations."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime
import json
from pathlib import Path
import runpy
import subprocess
import sys
import uuid

from tls_support import ROOT, ACTORS, compose, current_mode, log_record, probe, switch_mode

MODULES = {"S7": "s07_splice.py", "S8": "s08_selective.py", "S9": "s09_bypass.py", "SUPPORT": "s08_selective.py"}


def worktime(mode: str) -> None:
    path = ROOT / "policy/generated/work_hours.conf"
    values = {"never": "acl work_hours src 192.0.2.254/32",
              "always": "acl work_hours time 00:00-23:59",
              "real": "acl work_hours time MTWHF 08:00-17:00"}
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(values[mode] + "\n", encoding="utf-8")
    temporary.replace(path)
    output = compose("exec", "-T", "squid", "squid", "-k", "parse")
    if "ERROR" in output.stderr or "FATAL" in output.stderr:
        raise RuntimeError(output.stderr)
    compose("exec", "-T", "squid", "squid", "-k", "reconfigure")


def execute(case: dict, runid: str, observations: dict) -> tuple[bool, str, str]:
    kind = case.get("kind", "probe")
    test_id = f"{runid}.{case['id']}"
    url = case.get("url", "").replace("{runid}", runid + "-" + case["id"])
    if case.get("requires_policy"):
        present = compose("exec", "-T", "squid", "bash", "-c",
                          "grep -Eq '^http_access deny doh_providers' /etc/squid/conf.d/40-access.conf", check=False)
        if present.returncode:
            return False, "POL-3 missing; external request was not sent", "BLOCK:doh"
    if kind == "logcheck":
        record = log_record(f"{runid}.{case['source']}")
        ok = bool(record) and all(record.get(key) == value for key, value in case["fields"].items())
        return ok, json.dumps(record, ensure_ascii=False), str(case["fields"])
    if kind == "cmd":
        result = compose("exec", "-T", case["service"], *case["command"], check=False)
        text = result.stdout + result.stderr
        return (result.returncode != 0 and case["contains"] in text,
                f"exit={result.returncode} {text.strip()}", "CONN_FAIL")
    if kind == "sni_probe":
        service, credential = ACTORS[case["actor"]]
        result = compose("exec", "-T", "-e", "LAB_PROXY_CREDENTIAL=" + credential,
                         service, "python3", "/opt/lab/sni_probe.py", case["host"], case["sni"],
                         test_id, timeout=20)
        observed = json.loads(result.stdout)
        record = log_record(test_id)
        ok = observed["outcome"] == "TLS_ERROR" and bool(record and record["policy"] == "sni-threat")
        return ok, json.dumps(dict(probe=observed, log=record)), "TLS_ERROR + sni-threat"
    result = probe(case["actor"], url, test_id, case.get("options"))
    observations[case["id"]] = result
    if kind == "repeat":
        first = log_record(test_id)
        second = probe(case["actor"], url, test_id + ".repeat", case.get("options"))
        record = log_record(test_id + ".repeat")
        hit = bool(record and "HIT" in (record["result"] or ""))
        ok = result["outcome"] == second["outcome"] == "ALLOW" and hit == case["hit"] and record is not None
        return ok, json.dumps(dict(first=first, second=record, seconds=[result["time_total"], second["time_total"]])), f"cache HIT={case['hit']}"
    ok = result["outcome"] == case["expect"]
    if case.get("reason"):
        ok = ok and result["reason"] == case["reason"]
    if case.get("expect_issuer"):
        ok = ok and case["expect_issuer"] in (result["issuer"] or "")
    record = log_record(test_id)
    return ok, json.dumps(dict(probe=result, log=record), ensure_ascii=False), case["expect"] + (":" + case["reason"] if case.get("reason") else "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=MODULES)
    parser.add_argument("--case", action="append", help="select an exact ID; repeatable")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    scenarios = [args.scenario] if args.scenario else ["S7", "S8", "S9"]
    modules = {name: runpy.run_path(str(ROOT / "tests/scenarios" / MODULES[name])) for name in scenarios}
    selected = [(name, case, data["DEFAULT_STATE"]) for name, data in modules.items()
                for case in data["SUPPORT_CASES" if name == "SUPPORT" else "CASES"] if not args.case or case["id"] in args.case]
    if not selected:
        parser.error("no matching cases")
    if args.list:
        for name, case, _ in selected:
            print(name, case["id"], case.get("kind", "probe"), case.get("expect", ""))
        return 0
    previous = current_mode()
    hours_path = ROOT / "policy/generated/work_hours.conf"
    original_hours = hours_path.read_bytes() if hours_path.exists() else None
    runid = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    directory = ROOT / "results/tls" / runid
    directory.mkdir(parents=True)
    rows, observations = [], {}
    active_state = {}
    try:
        for scenario, case, default_state in selected:
            state = dict(default_state, **case.get("state", {}))
            try:
                if state.get("tls") != active_state.get("tls"):
                    switch_mode(state["tls"])
                if state.get("worktime") != active_state.get("worktime"):
                    worktime(state["worktime"])
                active_state = state
                ok, evidence, expected = execute(case, runid, observations)
                status = ("PASS (limitation)" if case.get("limitation") else "PASS") if ok else "FAIL"
            except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as error:
                status, evidence, expected = "FAIL", str(error), str(case.get("expect", case.get("kind")))
            row = dict(ID=case["id"], Scenario=scenario, Actor=case.get("actor", ""),
                       URL=case.get("url", ""), State=json.dumps(state), Expected=expected,
                       Status=status, Evidence=evidence)
            rows.append(row)
            print(f"{case['id']}: {status}", flush=True)
    finally:
        try:
            if original_hours is not None:
                hours_path.write_bytes(original_hours)
            elif hours_path.exists():
                hours_path.unlink()
            switch_mode(previous)
        except Exception as error:
            rows.append(dict(ID="RESTORE", Scenario="", Actor="", URL="", State="", Expected="restore original state", Status="FAIL", Evidence=str(error)))
        if rows:
            with (directory / "results.csv").open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
            text = ["# TV2 acceptance results", "", "Dependencies: POL-2/3/5 and THR-4 are required for full acceptance.", "",
                    "| ID | Scenario | Expected | Status | Evidence |", "|---|---|---|---|---|"]
            for row in rows:
                evidence = row["Evidence"].replace("|", "\\|").replace("\n", " ")
                text.append(f"| {row['ID']} | {row['Scenario']} | {row['Expected']} | {row['Status']} | {evidence} |")
            (directory / "results.md").write_text("\n".join(text) + "\n", encoding="utf-8")
    print(directory / "results.md")
    return int(any(row["Status"] == "FAIL" for row in rows))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError) as error:
        print(f"TV2 preflight failed: {error}", file=sys.stderr)
        sys.exit(2)
