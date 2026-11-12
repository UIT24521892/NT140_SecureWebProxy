"""S10: cache and guest bandwidth limit (spec §13 S10, P1). Owner: POL-6."""
from pathlib import Path

from tests.lib.model import Case


def guest_rate() -> int:
    """GUEST_RATE_BYTES from .env, or the default of spec §5.7."""
    env = Path(__file__).resolve().parents[2] / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            if line.startswith("GUEST_RATE_BYTES="):
                return int(line.split("=", 1)[1])
    return 262144


RATE = guest_rate()
CACHE = "http://cache.lab.test"

CASES = [
    Case(id="T10.1", kind="repeat", actor="alice", url=CACHE + "/cacheable/{runid}/10m.bin",
         hit=True, note="first request MISS, second HIT"),
    Case(id="T10.2", kind="repeat", actor="alice", url=CACHE + "/nocache/1m.bin",
         hit=False, note="Cache-Control: no-store"),
    Case(id="T10.3", actor="guest", url=CACHE + "/cacheable/{runid}/2m.bin", expect="ALLOW",
         max_speed=1.2 * RATE, note="guest is rate limited"),
    Case(id="T10.4", actor="alice", url=CACHE + "/cacheable/{runid}/2m.bin", expect="ALLOW",
         min_speed=4 * RATE, note="staff is not rate limited"),
]
for _case in CASES:
    _case.priority = "P1"
