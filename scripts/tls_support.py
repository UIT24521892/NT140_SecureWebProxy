"""TV2 Docker helpers; stdlib only. THR can keep its own runner (spec §11)."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]


def compose(*args: str, check: bool = True, stdin: str | None = None,
            timeout: float = 120) -> subprocess.CompletedProcess:
    command = shlex.split(os.environ.get("COMPOSE", "docker compose")) + list(args)
    result = subprocess.run(command, cwd=ROOT, input=stdin, text=True, encoding="utf-8",
                            errors="replace", capture_output=True, timeout=timeout)
    if check and result.returncode:
        # Do not include command arguments: probe commands can contain lab passwords.
        raise RuntimeError((result.stderr or result.stdout).strip() or "Docker command failed")
    return result


def env_values() -> dict[str, str]:
    path = ROOT / ".env"
    result = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                result[key] = value
    return result


def set_env(key: str, value: str) -> None:
    path = ROOT / ".env"
    source = path if path.exists() else ROOT / ".env.example"
    lines = [line for line in source.read_text(encoding="utf-8").splitlines()
             if not line.startswith(key + "=")]
    lines.append(f"{key}={value}")
    temp = path.with_suffix(".tls.tmp")
    temp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temp.chmod(0o600)
    temp.replace(path)


def current_mode() -> str:
    return compose("exec", "-T", "squid", "cat", "/run/nt140-tls-mode").stdout.strip()


def switch_mode(mode: str, persist: bool = False) -> None:
    if mode not in ("splice", "bump", "selective"):
        raise ValueError("TLS mode must be splice|bump|selective")
    compose("exec", "-T", "squid", "/usr/local/lib/nt140/switch-tls.sh", mode)
    # Give the asynchronous reload a settling period. Probes use fresh connections.
    time.sleep(0.5)
    if persist:
        set_env("TLS_MODE", mode)


ACTORS = {
    "guest": ("client-guest", None), "anon": ("client-staff", None),
    "badpass": ("client-staff", "alice:wrong"),
    "alice": ("client-staff", "alice:alice123"),
    "bob": ("client-staff", "bob:bob123"),
    "admin1": ("client-staff", "admin1:admin123"),
    "alice-unmanaged": ("client-staff", "alice:alice123"),
}


def probe(actor: str, url: str, test_id: str, options: list[str] | None = None,
          keylog: str | None = None) -> dict:
    service, credential = ACTORS[actor]
    args = ["exec", "-T"]
    if keylog:
        args += ["-e", f"SSLKEYLOGFILE={keylog}"]
    args += [service, "bash", "/opt/lab/probe.sh", "-t", test_id]
    if credential:
        args += ["-u", credential]
    if actor == "alice-unmanaged":
        args += ["--cacert", "/opt/certs/lab-public-ca.crt"]
    result = compose(*args, *(options or []), url)
    return json.loads(result.stdout)


def log_record(test_id: str, timeout: float = 2) -> dict | None:
    # Load by file path so an unrelated installed `tests` package cannot shadow ours.
    import importlib.util
    spec = importlib.util.spec_from_file_location("nt140_squidlog", ROOT / "tests/lib/squidlog.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    deadline = time.monotonic() + timeout
    best = None
    while True:
        records = module.records_for(test_id)
        if records:
            best = records[-1]
            if best["result"] != "NONE_NONE":
                return best
        trace = ROOT / "logs/squid/access_tls.log"
        if trace.exists():
            parsed = []
            with trace.open(encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    fields = line.rstrip("\r\n").split("\t")
                    if len(fields) == 17:
                        record = module.parse_line("\t".join(fields[:16]))
                        parsed.append((record, fields[16]))
            anchors = [(index, (record["client_ip"], port)) for index, (record, port)
                       in enumerate(parsed) if record["test_id"] == test_id]
            for index, connection in reversed(anchors):
                matches = [record for record, port in parsed[index:]
                           if (record["client_ip"], port) == connection]
                completed = [record for record in matches if record["result"] != "NONE_NONE"]
                if completed:
                    result = dict(completed[-1])
                    # Keep the raw missing test_id intact; expose how it was joined.
                    result["matched_test_id"] = test_id
                    result["evidence_source"] = "access_tls.log; joined on client IP + port"
                    return result
        if time.monotonic() >= deadline:
            return best
        time.sleep(0.1)
