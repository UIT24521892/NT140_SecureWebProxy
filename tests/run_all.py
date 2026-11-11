#!/usr/bin/env python3
"""NT140 test runner (spec §11). Owner: THR-2.

    python3 tests/run_all.py [--scenario S5] [--priority P0|P1|all] [--list]

Scenarios are modules tests/scenarios/sNN_<name>.py exposing CASES (Case objects or
dicts with the same fields) and optionally DEFAULT_STATE. Expectations come from
spec §13 and are never adjusted to match what the lab returns.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import runpy
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tests.lib import lab, report, squidlog  # noqa: E402
from tests.lib.model import (ACTORS, DEFAULT_STATE, FAIL, PASS, PASS_LIMITATION,  # noqa: E402
                             SKIP, Case, Result)

SCENARIO_DIR = REPO_ROOT / "tests" / "scenarios"
SAMPLE_SEED = 140  # fixed so probe_sample picks the same hosts on every run


class Runner:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.state = lab.StateManager()
        self.ran: set[str] = set()  # ids of cases that sent a request

    def test_id(self, case_id: str) -> str:
        return f"{self.run_id}.{case_id}"

    # --- helpers ---------------------------------------------------------
    def probe(self, case: Case, url: str, test_id: str, extra: tuple[str, ...] = ()) -> dict:
        if not lab.PROBE.exists():
            raise lab.Unavailable("tests/probe/probe.sh missing (TLS-2)")
        actor = ACTORS[case.actor or ""]
        cmd = ["/opt/lab/probe.sh", "-t", test_id]
        if actor.credential:
            cmd += ["-u", actor.credential]
        cmd += [*actor.probe_args, *case.options, *extra, url]
        out = lab.exec_in(actor.service, cmd)
        lines = out.stdout.strip().splitlines()
        try:
            return json.loads(lines[-1])
        except (IndexError, json.JSONDecodeError):
            raise RuntimeError(f"probe gave no JSON (exit {out.returncode}): "
                               f"{(out.stderr or out.stdout).strip()[:200]}") from None

    def url_of(self, case: Case) -> str:
        return (case.url or "").replace("{runid}", self.run_id)

    @staticmethod
    def outcome_text(res: dict) -> str:
        text = res["outcome"] + (f":{res['reason']}" if res.get("reason") else "")
        return f"{text} (http={res.get('http_code')} connect={res.get('connect_code')})"

    @staticmethod
    def matches(case: Case, res: dict) -> bool:
        return (res["outcome"] == case.expect
                and (case.reason is None or res.get("reason") == case.reason))

    # --- kinds -----------------------------------------------------------
    def run_probe(self, case: Case) -> tuple[bool, str, str]:
        if case.requires_policy and case.reason and not lab.squid_has_rule(case.reason):
            raise lab.Unavailable(f"squid has no deny rule for '{case.reason}' (POL-3); "
                                  "request not sent")
        tid = self.test_id(case.id)
        res = self.probe(case, self.url_of(case), tid)
        self.ran.add(case.id)
        ok = self.matches(case, res)
        observed = self.outcome_text(res)
        if case.expect_issuer:
            ok = ok and case.expect_issuer in (res.get("issuer") or "")
            observed += f" issuer={res.get('issuer')}"
        if case.min_speed is not None or case.max_speed is not None:
            speed = float(res.get("speed") or 0)
            ok = ok and (case.min_speed is None or speed > case.min_speed)
            ok = ok and (case.max_speed is None or speed <= case.max_speed)
            observed += f" speed={speed:.0f}B/s"
        return ok, observed, squidlog.evidence(squidlog.best_record(tid))

    def run_repeat(self, case: Case) -> tuple[bool, str, str]:
        tid, url = self.test_id(case.id), self.url_of(case)
        first = self.probe(case, url, tid)
        rec1 = squidlog.best_record(tid)
        second = self.probe(case, url, tid + ".repeat")
        rec2 = squidlog.best_record(tid + ".repeat")
        self.ran.add(case.id)
        hit = rec2 is not None and "HIT" in (rec2["result"] or "")
        ok = (first["outcome"] == second["outcome"] == "ALLOW" and rec2 is not None
              and (case.hit is None or hit == case.hit))
        observed = (f"1st {first['outcome']} {(rec1 or {}).get('result')} {first['time_total']}s, "
                    f"2nd {second['outcome']} {(rec2 or {}).get('result')} {second['time_total']}s")
        return ok, observed, squidlog.evidence(rec2)

    def run_sample(self, case: Case) -> tuple[bool, str, str]:
        path = REPO_ROOT / (case.list_file or "")
        hosts = sorted({line.strip().lstrip(".") for line in
                        (path.read_text(encoding="utf-8").splitlines() if path.exists() else [])
                        if line.strip() and not line.lstrip().startswith("#")})
        if not hosts:
            raise lab.Unavailable(f"{case.list_file} is empty or missing (run `make feeds`)")
        # Safety (spec §12.3): without this rule a dryrun request would reach the feed host.
        guard = lab.exec_in("squid", ["grep", "-Eqrs", r"^never_direct allow dryrun",
                                      "/etc/squid/conf.d/"])
        if guard.returncode != 0:
            raise lab.Unavailable("squid has no `never_direct allow dryrun` (THR-5); "
                                  "feed hosts are not probed")
        picked = random.Random(SAMPLE_SEED).sample(hosts, min(case.sample, len(hosts)))
        good, misses = 0, []
        for n, host in enumerate(picked, 1):
            res = self.probe(case, f"http://{host}/", f"{self.test_id(case.id)}.{n}", ("--dryrun",))
            if self.matches(case, res):
                good += 1
            else:
                misses.append(f"{host}={res['outcome']}")
        self.ran.add(case.id)
        rate = good / len(picked)
        return (rate >= case.min_rate, f"{good}/{len(picked)} matched ({rate:.0%})",
                "misses: " + ", ".join(misses[:5]) if misses else "all sampled hosts matched")

    def run_logcheck(self, case: Case) -> tuple[bool, str, str]:
        if case.source not in self.ran:
            raise lab.Unavailable(f"source case {case.source} did not run")
        tid = self.test_id(case.source or "")
        squidlog.best_record(tid)  # wait for the asynchronous logger
        records = squidlog.all_records(tid) + squidlog.all_records(tid + ".repeat")

        def field_ok(rec: dict, name: str, want: Any) -> bool:
            have = rec.get(name)
            return have == want or (have is not None
                                    and re.fullmatch(str(want), str(have)) is not None)

        good = [r for r in records if all(field_ok(r, k, v) for k, v in case.fields.items())]
        shown = good[-1] if good else (records[-1] if records else None)
        observed = ("no log line" if shown is None else
                    ", ".join(f"{k}={shown.get(k)}" for k in case.fields))
        return bool(good), observed, squidlog.evidence(shown)

    def run_cmd(self, case: Case) -> tuple[bool, str, str]:
        if case.service in ("host", "labvm"):
            out = lab.run(case.command)
        else:
            lab.require_service(case.service or "")
            out = lab.exec_in(case.service or "", case.command)
        text = out.stdout + out.stderr
        ok = ((out.returncode != 0) == case.nonzero
              and (case.contains is None or case.contains in text)
              and (case.not_contains is None or case.not_contains not in text))
        self.ran.add(case.id)
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        shown = lines[-1] if lines else ""
        if case.contains and case.contains in text:
            at = text.index(case.contains)
            shown = text[max(0, at - 40):at + len(case.contains) + 40]
        return ok, f"exit={out.returncode}", " ".join(shown.split())[:160]

    def run_sni(self, case: Case) -> tuple[bool, str, str]:
        if not lab.SNI_PROBE.exists():
            raise lab.Unavailable("tests/probe/sni_probe.py missing (TLS-4)")
        actor, tid = ACTORS[case.actor or ""], self.test_id(case.id)
        out = lab.exec_in(actor.service, ["python3", "/opt/lab/sni_probe.py",
                                          case.host or "", case.sni or "", tid],
                          env={"LAB_PROXY_CREDENTIAL": actor.credential or ""}, timeout=30)
        try:
            res = json.loads(out.stdout.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError):
            raise RuntimeError(f"sni_probe gave no JSON: {out.stderr.strip()[:200]}") from None
        self.ran.add(case.id)
        squidlog.find_by_test_id(tid)
        recs = squidlog.all_records(tid)
        rec = next((r for r in recs if case.policy and r["policy"] == case.policy), recs[-1] if recs else None)
        ok = res.get("outcome") == case.expect
        if case.policy:
            ok = ok and rec is not None and rec["policy"] == case.policy
        return ok, str(res.get("outcome")), squidlog.evidence(rec)

    # --- driver ----------------------------------------------------------
    def run_case(self, case: Case, defaults: dict[str, Any]) -> Result:
        wanted = {**defaults, **case.state}
        handler = {"probe": self.run_probe, "repeat": self.run_repeat,
                   "probe_sample": self.run_sample, "logcheck": self.run_logcheck,
                   "cmd": self.run_cmd, "sni_probe": self.run_sni}[case.kind]
        try:
            self.state.apply(wanted)
            ok, observed, evidence = handler(case)
        except lab.Unavailable as exc:
            return Result(case, SKIP, "not run", str(exc), wanted)
        except (RuntimeError, OSError, KeyError, subprocess.SubprocessError) as exc:
            return Result(case, FAIL, "runner error", f"{type(exc).__name__}: {exc}", wanted)
        status = (PASS_LIMITATION if case.limitation else PASS) if ok else FAIL
        return Result(case, status, observed, evidence, wanted)

    def run_scenario(self, cases: list[Case], defaults: dict[str, Any]) -> list[Result]:
        def key(case: Case) -> str:
            return json.dumps({**defaults, **case.state}, sort_keys=True)

        # Group cases with the same state to limit reconfigures, keeping first-seen
        # order of the groups (S5 relies on its ICAP-down cases staying last, spec §7).
        # Log checks run last, once the cases they inspect have been executed.
        direct = [c for c in cases if c.kind != "logcheck"]
        order = list(dict.fromkeys(key(c) for c in direct))
        direct.sort(key=lambda c: order.index(key(c)))
        done = {c.id: self.run_case(c, defaults)
                for c in direct + [c for c in cases if c.kind == "logcheck"]}
        return [done[c.id] for c in cases]


def load_scenarios() -> dict[str, tuple[list[Case], dict[str, Any]]]:
    found: dict[str, tuple[list[Case], dict[str, Any]]] = {}
    for path in sorted(SCENARIO_DIR.glob("s[0-9][0-9]_*.py")):
        name = f"S{int(path.name[1:3])}"
        module = runpy.run_path(str(path))
        cases = [c if isinstance(c, Case) else Case.from_dict(dict(c))
                 for c in module.get("CASES", [])]
        for case in cases:
            case.scenario = name
        found[name] = (cases, dict(module.get("DEFAULT_STATE", DEFAULT_STATE)))
    ids = [c.id for cases, _ in found.values() for c in cases]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise ValueError(f"duplicate case ids: {dupes}")
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="NT140 Secure Web Gateway test runner (spec §11)")
    ap.add_argument("--scenario", action="append", metavar="S5",
                    help="run only this scenario (repeatable)")
    ap.add_argument("--priority", choices=("P0", "P1", "all"), default="all")
    ap.add_argument("--list", action="store_true", help="list the selected cases and exit")
    args = ap.parse_args(argv)

    try:
        scenarios = load_scenarios()
    except (ValueError, TypeError) as exc:
        print(f"run_all: bad scenario module: {exc}", file=sys.stderr)
        return 2
    wanted = [s.upper() for s in args.scenario or scenarios]
    unknown = [s for s in wanted if s not in scenarios]
    if unknown:
        print(f"run_all: no scenario module for {', '.join(unknown)} "
              f"(available: {', '.join(scenarios) or 'none'})", file=sys.stderr)
        return 2
    selected = {s: ([c for c in scenarios[s][0]
                     if args.priority == "all" or c.priority == args.priority], scenarios[s][1])
                for s in wanted}
    if not any(cases for cases, _ in selected.values()):
        print("run_all: no case matches the selection", file=sys.stderr)
        return 2
    if args.list:
        for name, (cases, _) in selected.items():
            for c in cases:
                print(f"{name}\t{c.id}\t{c.priority}\t{c.kind}\t{c.expected_text}")
        return 0

    try:
        if "squid" not in lab.running_services():
            print("run_all: squid is not running, start the lab with `make up`", file=sys.stderr)
            return 2
    except (RuntimeError, OSError) as exc:
        print(f"run_all: {exc}", file=sys.stderr)
        return 2

    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    runner = Runner(run_id)
    results: list[Result] = []
    errors: list[str] = []
    try:
        for name, (cases, defaults) in selected.items():
            if not cases:
                continue
            for res in runner.run_scenario(cases, defaults):
                results.append(res)
                print(f"{res.case.id:<7} {res.status:<18} {res.observed}  [{res.evidence}]",
                      flush=True)
            errors += runner.state.restore(DEFAULT_STATE)
    finally:
        errors += runner.state.restore(DEFAULT_STATE)
        if results:
            md = report.write(results, REPO_ROOT / "results" / run_id, run_id,
                              ["tests/run_all.py", *(argv if argv is not None else sys.argv[1:])])
            print(f"\n{report.summary(results)}\n{md.relative_to(REPO_ROOT)}")
    for err in errors:
        print(f"run_all: state not restored: {err}", file=sys.stderr)
    return 1 if errors or any(r.status == FAIL for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
