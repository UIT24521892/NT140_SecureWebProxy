"""Case model and fixed vocabulary of the test runner (spec §11). Owner: THR-2."""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any

OUTCOMES = ("ALLOW", "BLOCK", "AUTH_REQUIRED", "TLS_ERROR", "CONN_FAIL", "UPSTREAM_ERROR")
KINDS = ("probe", "probe_sample", "logcheck", "cmd", "sni_probe", "repeat")
PRIORITIES = ("P0", "P1", "P2")

PASS, PASS_LIMITATION, FAIL, SKIP = "PASS", "PASS (limitation)", "FAIL", "SKIP"

# Default state of every scenario (spec §11). A module may override it with DEFAULT_STATE.
DEFAULT_STATE: dict[str, Any] = {
    "tls": "selective", "worktime": "never", "icap_bypass": "off", "icap_running": True,
}
STATE_VALUES: dict[str, tuple] = {
    "tls": ("splice", "bump", "selective"),
    "worktime": ("real", "always", "never"),
    "icap_bypass": ("on", "off"),
    "icap_running": (True, False),
}


@dataclass(frozen=True)
class Actor:
    service: str
    credential: str | None = None
    probe_args: tuple[str, ...] = ()


# spec §11 actor table. Passwords are the lab accounts of spec §4.
ACTORS: dict[str, Actor] = {
    "guest": Actor("client-guest"),
    "anon": Actor("client-staff"),
    "badpass": Actor("client-staff", "alice:wrong"),
    "alice": Actor("client-staff", "alice:alice123"),
    "bob": Actor("client-staff", "bob:bob123"),
    "admin1": Actor("client-staff", "admin1:admin123"),
    "alice-unmanaged": Actor("client-staff", "alice:alice123",
                             ("--cacert", "/opt/certs/lab-public-ca.crt")),
}


@dataclass
class Case:
    id: str
    kind: str = "probe"
    actor: str | None = None
    url: str | None = None            # "{runid}" is replaced by a unique token per run
    expect: str | None = None         # outcome, or "BLOCK:social" as written in spec §13
    reason: str | None = None
    limitation: bool = False
    state: dict[str, Any] = field(default_factory=dict)
    expect_issuer: str | None = None  # substring of the certificate issuer
    priority: str = "P0"
    note: str = ""
    options: list[str] = field(default_factory=list)  # extra probe.sh flags
    requires_policy: bool = False     # SKIP unless squid has a deny rule for `reason`
    min_speed: float | None = None    # probe: bytes/s bounds on the `speed` field
    max_speed: float | None = None
    # logcheck
    source: str | None = None         # id of the case whose log line is checked
    fields: dict[str, Any] = field(default_factory=dict)  # log field -> value or regex
    # cmd
    service: str | None = None        # compose service, or "host" to run on the lab host
    command: list[str] = field(default_factory=list)
    nonzero: bool = False             # expect a non-zero exit code
    contains: str | None = None
    not_contains: str | None = None
    # sni_probe
    host: str | None = None
    sni: str | None = None
    policy: str | None = None         # expected `policy` note in the log line
    # repeat
    hit: bool | None = None           # expected cache HIT on the second request
    # probe_sample
    list_file: str | None = None      # path relative to the repo root
    sample: int = 20
    min_rate: float = 1.0
    scenario: str = ""                # filled in by the runner

    def __post_init__(self) -> None:
        if self.expect and ":" in self.expect and self.reason is None:
            self.expect, self.reason = self.expect.split(":", 1)
        problems = []
        if self.kind not in KINDS:
            problems.append(f"kind={self.kind!r}")
        if self.priority not in PRIORITIES:
            problems.append(f"priority={self.priority!r}")
        if self.actor is not None and self.actor not in ACTORS:
            problems.append(f"actor={self.actor!r}")
        if self.kind in ("probe", "probe_sample", "sni_probe") and self.expect not in OUTCOMES:
            problems.append(f"expect={self.expect!r}")
        for key, value in self.state.items():
            if value not in STATE_VALUES.get(key, ()):
                problems.append(f"state {key}={value!r}")
        if problems:
            raise ValueError(f"case {self.id}: invalid " + ", ".join(problems))

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        known = {f.name for f in fields(cls)}
        unknown = sorted(set(data) - known)
        if unknown:
            raise ValueError(f"case {data.get('id')}: unknown keys {unknown}")
        return cls(**data)

    @property
    def expected_text(self) -> str:
        if self.kind == "logcheck":
            return "log " + ", ".join(f"{k}={v}" for k, v in self.fields.items())
        if self.kind == "cmd":
            parts = ["exit!=0" if self.nonzero else "exit=0"]
            if self.contains:
                parts.append(f"contains {self.contains!r}")
            if self.not_contains:
                parts.append(f"lacks {self.not_contains!r}")
            return ", ".join(parts)
        if self.kind == "repeat":
            return "2nd request " + {True: "HIT", False: "not HIT", None: "any"}[self.hit]
        text = self.expect or ""
        if self.reason:
            text += f":{self.reason}"
        if self.expect_issuer:
            text += f", issuer~{self.expect_issuer}"
        if self.policy:
            text += f", log policy={self.policy}"
        if self.kind == "probe_sample":
            text += f" >= {self.min_rate:.0%} of {self.sample}"
        return text


@dataclass
class Result:
    case: Case
    status: str
    observed: str = ""
    evidence: str = ""
    state: dict[str, Any] = field(default_factory=dict)
