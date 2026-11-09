#!/usr/bin/env python3
"""Measure B1-B8; missing scan/cache prerequisites are explicit, never fabricated."""
from __future__ import annotations

import argparse
import csv
from datetime import datetime
import json
import math
import re
import statistics
import sys
import uuid

from tls_support import ROOT, compose, current_mode, log_record, probe, switch_mode


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def write_icap(content: str) -> None:
    compose("exec", "-T", "squid", "bash", "-c",
            "cat > /etc/squid/conf.d/30-icap.conf; squid -k parse >&2 && squid -k reconfigure", stdin=content)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=50)
    parser.add_argument("--config", action="append", choices=[f"B{i}" for i in range(1, 9)])
    args = parser.parse_args()
    if args.requests < 1:
        parser.error("--requests must be positive")
    original_mode = current_mode()
    icap = compose("exec", "-T", "squid", "cat", "/etc/squid/conf.d/30-icap.conf", check=False)
    scan_ready = icap.returncode == 0 and "icap" in compose("ps", "--status", "running", "--services").stdout.split()
    cache_ready = compose("exec", "-T", "squid", "bash", "-c",
                          "grep -Eq '^[[:space:]]*cache_dir[[:space:]]' /etc/squid/conf.d/*.conf", check=False).returncode == 0
    runid = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    directory = ROOT / "results/bench" / runid
    directory.mkdir(parents=True)
    architecture = compose("exec", "-T", "squid", "uname", "-m").stdout.strip()
    version = compose("exec", "-T", "squid", "squid", "-v").stdout.splitlines()[0]
    metadata = dict(architecture=architecture, squid=version, requests=args.requests,
                    icap_ready=scan_ready, cache_configured=cache_ready, original_mode=original_mode)
    (directory / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    rows, samples, statistics_rows = [], [], []
    failed = False
    try:
        for number in range(1, 9):
            name = f"B{number}"
            if args.config and name not in args.config:
                continue
            reason = ("THR-4: ICAP is not configured and running" if number in (4, 8) and not scan_ready
                      else "POL-5: cache is not configured" if number == 3 and not cache_ready else "")
            if reason:
                rows.append(dict(config=name, payload="all", status="SKIP", count=0, avg=0, p50=0, p95=0, note=reason))
                print(f"{name}: SKIP ({reason})", flush=True)
                continue
            if icap.returncode == 0:
                disabled = re.sub(r"(?m)^adaptation_access\s+svc_av\s+.*$", "adaptation_access svc_av deny all", icap.stdout)
                if number not in (4, 8) and disabled == icap.stdout:
                    raise RuntimeError("cannot safely disable svc_av in the installed ICAP configuration")
                write_icap(icap.stdout if number in (4, 8) else disabled)
            switch_mode("splice" if number == 6 else "selective")
            for payload in ("html", "1m"):
                elapsed = []
                status, note = "PASS", ""
                for index in range(args.requests):
                    test_id = f"bench-{runid}-{name}-{payload}-{index}"
                    # The fixed HIT path is warmed immediately before measuring.
                    path_id = f"{runid}/{name}/{payload}/" + ("hit" if number == 3 else str(index))
                    path = "/" if payload == "html" else f"/cacheable/{path_id}/1m.bin"
                    # A unique path is also needed for small HTML MISS measurements.
                    if payload == "html":
                        path = f"/bench/{path_id}/"
                    scheme = "https" if number >= 5 else "http"
                    url = f"{scheme}://cache.lab.test{path}"
                    if number in (1, 5):
                        result = compose("exec", "-T", "squid", "curl", "--disable", "--silent", "--show-error",
                                         "--noproxy", "*", "--max-time", "30", "-o", "/dev/null", "-w", "%{json}", url)
                        metrics = json.loads(result.stdout)
                        if int(metrics["http_code"]) != 200:
                            raise RuntimeError(f"{name}: origin returned {metrics['http_code']}")
                        seconds = metrics["time_total"]
                        size, cache_result, bump_mode = int(metrics["size_download"]), "DIRECT", "-"
                    else:
                        if number == 3:
                            warm = probe("alice", url, test_id + "-warm")
                            if warm["outcome"] != "ALLOW":
                                raise RuntimeError("cache warmup failed")
                        observed = probe("alice", url, test_id)
                        if observed["outcome"] != "ALLOW":
                            raise RuntimeError(f"{name}: {observed['outcome']}")
                        record = log_record(test_id)
                        if not record:
                            raise RuntimeError(f"{name}: missing request log")
                        hit = "HIT" in (record["result"] or "")
                        if (number == 3 and not hit) or (number in (2, 4, 7, 8) and hit):
                            status, note = "FAIL", f"unexpected cache result: {record['result']}"
                            failed = True
                        seconds = observed["time_total"]
                        size, cache_result, bump_mode = observed["size"], record["result"], record["bump_mode"]
                    elapsed.append(seconds)
                    samples.append(dict(config=name, payload=payload, index=index, time_total=seconds,
                                        bytes=size, cache_result=cache_result, bump_mode=bump_mode))
                resources = compose("stats", "--no-stream", "--format", "json", check=False).stdout
                statistics_rows.append(dict(config=name, payload=payload, docker_stats=resources))
                rows.append(dict(config=name, payload=payload, status=status, count=len(elapsed),
                                 avg=statistics.mean(elapsed), p50=percentile(elapsed, 0.5),
                                 p95=percentile(elapsed, 0.95), note=note))
                print(f"{name}/{payload}: {status}, n={len(elapsed)}", flush=True)
    finally:
        try:
            if icap.returncode == 0:
                write_icap(icap.stdout)
            switch_mode(original_mode)
        finally:
            for name, data in (("bench.csv", rows), ("samples.csv", samples)):
                if data:
                    with (directory / name).open("w", encoding="utf-8", newline="") as handle:
                        writer = csv.DictWriter(handle, fieldnames=list(data[0]))
                        writer.writeheader()
                        writer.writerows(data)
            (directory / "resources.json").write_text(json.dumps(statistics_rows, indent=2), encoding="utf-8")
            text = ["# TLS benchmark", "", f"Architecture: {architecture}. {version}.", "",
                    f"Requests per payload: {args.requests}. Times in seconds. HTML: 1024 bytes; binary: 1048576 bytes.", "",
                    "| Config | Payload | Status | N | Avg | p50 | p95 | Note |", "|---|---|---|---:|---:|---:|---:|---|"]
            for row in rows:
                text.append(f"| {row['config']} | {row['payload']} | {row['status']} | {row['count']} | {row['avg']:.6f} | {row['p50']:.6f} | {row['p95']:.6f} | {row['note']} |")
            (directory / "bench.md").write_text("\n".join(text) + "\n", encoding="utf-8")
    print(directory / "bench.md")
    return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        sys.exit(1)
