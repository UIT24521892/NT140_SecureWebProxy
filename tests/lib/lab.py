"""Docker Compose helpers and lab state management (spec §11). Owner: THR-2."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
PROBE = REPO_ROOT / "tests" / "probe" / "probe.sh"
SNI_PROBE = REPO_ROOT / "tests" / "probe" / "sni_probe.py"

# State key -> (script that applies it, task that delivers the script).
STATE_SCRIPTS = {
    "tls": ("scripts/set-tls-mode.sh", "TLS-3"),
    "worktime": ("scripts/set-worktime.sh", "POL-4"),
    "icap_bypass": ("scripts/set-icap.sh", "THR-4"),
}


class Unavailable(Exception):
    """A prerequisite of the case is not there yet; the case is reported as SKIP."""


def run(cmd: list[str], timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True,
                          errors="replace", timeout=timeout)


def compose(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return run(["docker", "compose", *args], timeout=timeout)


def exec_in(service: str, command: list[str], env: dict[str, str] | None = None,
            timeout: float = 120) -> subprocess.CompletedProcess:
    flags: list[str] = []
    for key, value in (env or {}).items():
        flags += ["-e", f"{key}={value}"]
    return compose("exec", "-T", *flags, service, *command, timeout=timeout)


def defined_services() -> set[str]:
    """Services of the active compose profiles. Profile-gated stubs are not listed."""
    out = compose("config", "--services")
    if out.returncode != 0:
        raise RuntimeError(f"docker compose config failed: {out.stderr.strip()}")
    return set(out.stdout.split())


def running_services() -> set[str]:
    out = compose("ps", "--services", "--status", "running")
    if out.returncode != 0:
        raise RuntimeError(f"docker compose ps failed: {out.stderr.strip()}")
    return set(out.stdout.split())


def require_service(service: str) -> None:
    """Missing stub -> SKIP. A defined service that is down is a real failure."""
    if service not in defined_services():
        raise Unavailable(f"service {service} is not enabled in docker-compose.yml yet")
    if service not in running_services():
        raise RuntimeError(f"service {service} is not running")


def squid_has_rule(reason: str) -> bool:
    """True if squid's http_access has a deny line annotated with this reason."""
    mark = "mark_" + reason.replace("-", "_")
    out = exec_in("squid", ["grep", "-Eqs", rf"^http_access deny .*\b{mark}\b",
                            "/etc/squid/conf.d/40-access.conf"])
    return out.returncode == 0


class StateManager:
    """Applies tls / worktime / icap state and restores the defaults afterwards."""

    def __init__(self) -> None:
        self.current: dict[str, Any] = {}   # only what this run has applied itself
        self.touched: set[str] = set()

    def apply(self, wanted: dict[str, Any]) -> None:
        for key, value in wanted.items():
            if self.current.get(key, object()) == value:
                continue
            self._set(key, value)
            self.current[key] = value
            self.touched.add(key)

    def restore(self, defaults: dict[str, Any]) -> list[str]:
        """Put back the defaults for every key this run changed. Returns errors."""
        errors = []
        for key in sorted(self.touched):
            if key in defaults and self.current.get(key) != defaults[key]:
                try:
                    self._set(key, defaults[key])
                    self.current[key] = defaults[key]
                except (Unavailable, RuntimeError, subprocess.SubprocessError) as exc:
                    errors.append(f"restore {key}={defaults[key]}: {exc}")
        return errors

    def _set(self, key: str, value: Any) -> None:
        if key == "icap_running":
            self._icap_running(bool(value))
            return
        script, task = STATE_SCRIPTS[key]
        if not (REPO_ROOT / script).exists():
            raise Unavailable(f"{script} missing ({task}), cannot set {key}={value}")
        out = run([str(REPO_ROOT / script), str(value)])
        if out.returncode != 0:
            raise RuntimeError(f"{script} {value} failed: {(out.stderr or out.stdout).strip()}")

    @staticmethod
    def _icap_running(up: bool) -> None:
        if "icap" not in defined_services():
            raise Unavailable("service icap is not enabled in docker-compose.yml yet (THR-4)")
        out = (compose("up", "-d", "--wait", "icap", timeout=600) if up
               else compose("stop", "icap"))
        if out.returncode != 0:
            raise RuntimeError(f"icap {'start' if up else 'stop'} failed: {out.stderr.strip()}")
        if up:
            # Squid may keep the service marked down for icap_service_revival_delay (spec §7).
            exec_in("squid", ["squid", "-k", "reconfigure"])
