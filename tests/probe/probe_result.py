"""Convert curl artifacts to the stable probe JSON contract (TLS-2, spec §9.1)."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys


def classify(metrics: dict, exit_code: int, headers: str, body: str, verbose: str,
             test_id: str, url: str) -> dict:
    status = int(metrics.get("http_code", 0) or 0)
    connect = int(metrics.get("http_connect", 0) or 0)
    errors = re.findall(r"(?im)^X-Squid-Error:\s*(\S+)", headers + "\n" +
                        re.sub(r"(?m)^< ", "", verbose))
    squid_error = errors[-1] if errors else None
    marker = re.search(r"<!--\s*LAB-BLOCK\s+reason=([\w-]+)\s*-->", body)
    reason = None
    if 407 in (status, connect):
        outcome = "AUTH_REQUIRED"
    elif 403 in (status, connect):
        outcome = "BLOCK"
        reason = marker.group(1) if marker else "default"
        if not marker and squid_error and squid_error.startswith("ERR_LAB_"):
            reason = squid_error[len("ERR_LAB_"):].lower().replace("_", "-")
    elif exit_code in (35, 51, 58, 60, 90):
        outcome = "TLS_ERROR"
    elif exit_code in (6, 7, 28) and status == 0 and connect == 0:
        outcome = "CONN_FAIL"
    elif status >= 500 or connect >= 500 or exit_code != 0:
        outcome = "UPSTREAM_ERROR"
    elif 200 <= status < 300:
        outcome = "ALLOW"
    else:
        outcome = "UPSTREAM_ERROR"
    issuers = re.findall(r"(?im)^\*\s+issuer:\s*(.+)$", verbose)
    return {
        "test_id": test_id, "url": url, "outcome": outcome, "reason": reason,
        "http_code": status, "connect_code": connect, "curl_exit": exit_code,
        "squid_error": squid_error, "issuer": issuers[-1].strip() if issuers else None,
        "time_total": float(metrics.get("time_total", 0) or 0),
        "size": int(metrics.get("size_download", 0) or 0),
        "speed": float(metrics.get("speed_download", 0) or 0),
    }


def main() -> None:
    root = Path(sys.argv[1])
    metrics_text = (root / "metrics").read_text(encoding="utf-8", errors="replace")
    try:
        metrics = json.loads(metrics_text) if metrics_text.strip() else {}
    except json.JSONDecodeError:
        raise SystemExit("probe: curl did not produce valid JSON metrics") from None

    def read(name: str) -> str:
        path = root / name
        if not path.exists():
            return ""
        with path.open("rb") as handle:
            return handle.read(1024 * 1024).decode("utf-8", errors="replace")

    result = classify(metrics, int(sys.argv[2]), read("headers"), read("body"),
                      read("verbose"), sys.argv[3], sys.argv[4])
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    main()
