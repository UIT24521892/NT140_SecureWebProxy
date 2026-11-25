#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tests.lib import squidlog


def is_denied(record: dict) -> bool:
    result = str(record.get("result") or "").upper()
    status = record.get("status")

    return (
        "DENIED" in result
        or status in (403, 407)
        or str(record.get("policy") or "").lower() in {
            "phishing",
            "malware-content",
            "social",
            "games",
            "gambling",
            "path",
            "worktime",
            "sni-threat",
        }
    )


def decision(record: dict) -> str:
    return "DENY" if is_denied(record) else "ALLOW"


def domain(record: dict) -> str:
    url = str(record.get("url") or "")
    parsed = urlparse(url)

    if parsed.hostname:
        return parsed.hostname

    return "-"


def cache_state(record: dict) -> str | None:
    result = str(record.get("result") or "").upper()

    if "HIT" in result:
        return "HIT"

    if "MISS" in result:
        return "MISS"

    return None


def is_virus(record: dict) -> bool:
    values = [
        str(record.get("policy") or ""),
        str(record.get("result") or ""),
        str(record.get("mime") or ""),
        str(record.get("url") or ""),
    ]

    text = " ".join(values).lower()

    return any(
        marker in text
        for marker in (
            "virus",
            "eicar",
            "malware-content",
            "virus_found",
        )
    )


def load_records(path: Path) -> tuple[list[dict], int]:
    records = []
    malformed = 0

    if not path.exists():
        raise FileNotFoundError(f"log file not found: {path}")

    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue

            try:
                records.append(squidlog.parse_line(line))
            except squidlog.LogFormatError:
                malformed += 1

    return records, malformed


def nested_counts(records: list[dict], field: str) -> dict:
    output = defaultdict(Counter)

    for record in records:
        key = str(record.get(field) or "-")
        output[key][decision(record)] += 1

    return {
        key: {
            "ALLOW": counts.get("ALLOW", 0),
            "DENY": counts.get("DENY", 0),
        }
        for key, counts in sorted(output.items())
    }


def build_summary(records: list[dict], malformed: int) -> dict:
    allow = sum(decision(record) == "ALLOW" for record in records)
    deny = sum(decision(record) == "DENY" for record in records)

    policy_counts = Counter()
    blocked_domains = Counter()
    cache_counts = Counter()
    cache_bytes = Counter()
    bump_counts = Counter()
    virus_count = 0

    for record in records:
        current_decision = decision(record)
        policy = str(record.get("policy") or "-")
        policy_counts[(policy, current_decision)] += 1

        if current_decision == "DENY":
            blocked_domains[domain(record)] += 1

        cache = cache_state(record)
        if cache:
            cache_counts[cache] += 1
            cache_bytes[cache] += int(record.get("bytes") or 0)

        bump = str(record.get("bump_mode") or "").lower()
        if bump in {"splice", "bump"}:
            bump_counts[bump] += 1

        if is_virus(record):
            virus_count += 1

    total_cache_requests = cache_counts["HIT"] + cache_counts["MISS"]
    total_cache_bytes = cache_bytes["HIT"] + cache_bytes["MISS"]

    summary = {
        "input": "logs/squid/access_lab.log",
        "total_records": len(records),
        "malformed_records": malformed,
        "allow_deny": {
            "ALLOW": allow,
            "DENY": deny,
        },
        "by_policy": nested_counts(records, "policy"),
        "by_user": nested_counts(records, "user"),
        "by_client_ip": nested_counts(records, "client_ip"),
        "top_blocked_domains": [
            {"domain": name, "count": count}
            for name, count in blocked_domains.most_common(10)
        ],
        "cache": {
            "requests": {
                "HIT": cache_counts["HIT"],
                "MISS": cache_counts["MISS"],
                "hit_ratio": (
                    cache_counts["HIT"] / total_cache_requests
                    if total_cache_requests
                    else None
                ),
            },
            "bytes": {
                "HIT": cache_bytes["HIT"],
                "MISS": cache_bytes["MISS"],
                "hit_ratio": (
                    cache_bytes["HIT"] / total_cache_bytes
                    if total_cache_bytes
                    else None
                ),
            },
        },
        "tls": {
            "splice": bump_counts["splice"],
            "bump": bump_counts["bump"],
        },
        "virus_detected": virus_count,
    }

    return summary


def render_markdown(summary: dict) -> str:
    allow = summary["allow_deny"]["ALLOW"]
    deny = summary["allow_deny"]["DENY"]
    cache_requests = summary["cache"]["requests"]
    cache_bytes = summary["cache"]["bytes"]

    lines = [
        "# Squid access log summary",
        "",
        f"- Total records: **{summary['total_records']}**",
        f"- Malformed records: **{summary['malformed_records']}**",
        f"- ALLOW: **{allow}**",
        f"- DENY: **{deny}**",
        f"- Virus detected: **{summary['virus_detected']}**",
        "",
        "## Cache",
        "",
        f"- Request HIT: {cache_requests['HIT']}",
        f"- Request MISS: {cache_requests['MISS']}",
        f"- Request hit ratio: {cache_requests['hit_ratio']}",
        f"- Bytes HIT: {cache_bytes['HIT']}",
        f"- Bytes MISS: {cache_bytes['MISS']}",
        f"- Bytes hit ratio: {cache_bytes['hit_ratio']}",
        "",
        "## TLS",
        "",
        f"- Splice: {summary['tls']['splice']}",
        f"- Bump: {summary['tls']['bump']}",
        "",
        "## Top blocked domains",
        "",
        "| Domain | Count |",
        "|---|---:|",
    ]

    for item in summary["top_blocked_domains"]:
        lines.append(f"| `{item['domain']}` | {item['count']} |")

    if not summary["top_blocked_domains"]:
        lines.append("| None | 0 |")

    lines.extend(["", "## By policy", "", "| Policy | ALLOW | DENY |", "|---|---:|---:|"])

    for policy, counts in summary["by_policy"].items():
        lines.append(
            f"| `{policy}` | {counts['ALLOW']} | {counts['DENY']} |"
        )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="logs/squid/access_lab.log",
    )
    parser.add_argument(
        "--json",
        default="results/log_summary.json",
    )
    parser.add_argument(
        "--markdown",
        default="results/log_summary.md",
    )
    args = parser.parse_args()

    records, malformed = load_records(Path(args.input))
    summary = build_summary(records, malformed)

    json_path = Path(args.json)
    markdown_path = Path(args.markdown)

    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    markdown_path.write_text(
        render_markdown(summary),
        encoding="utf-8",
    )

    print(f"Wrote {json_path}")
    print(f"Wrote {markdown_path}")
    print(f"Records: {summary['total_records']}")
    print(f"ALLOW: {summary['allow_deny']['ALLOW']}")
    print(f"DENY: {summary['allow_deny']['DENY']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
