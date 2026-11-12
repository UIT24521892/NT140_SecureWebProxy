"""S0 smoke checks (spec §13 S0). Owner: THR-2."""
from tests.lib.model import Case

# Smoke checks do not depend on tls / worktime / icap state.
DEFAULT_STATE: dict = {}

CASES = [
    Case(id="T0.1", kind="cmd", service="squid", command=["squid", "-k", "parse"],
         not_contains="ERROR", note="squid.conf parses cleanly"),
    Case(id="T0.2", kind="cmd", service="squid", command=["squid", "-v"],
         contains="--with-openssl", note="squid-openssl build (SslBump available)"),
    # c-icap-client exits 0 even on 404, so the ICAP status line is what counts
    # (checked against c-icap 0.5.10 with the echo service, see docs/verify-log.md).
    Case(id="T0.3", kind="cmd", service="icap",
         command=["c-icap-client", "-i", "127.0.0.1", "-p", "1344", "-s", "virus_scan"],
         contains="ICAP/1.0 200 OK", note="ICAP OPTIONS on virus_scan"),
    Case(id="T0.4", kind="cmd", service="clamav", command=["clamdscan", "--ping", "1"],
         contains="PONG", note="clamd answers ping"),
    Case(id="T0.5", kind="cmd", service="squid",
         command=["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                  "http://allowed.lab.test/"],
         contains="200", note="squid reaches testweb directly"),
    Case(id="T0.6", kind="cmd", service="client-staff", command=["ip", "route"],
         not_contains="default", note="client has no default route (egress enforcement)"),
]
