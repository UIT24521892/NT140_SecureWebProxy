"""S5: scanning downloads with ICAP/ClamAV (spec §13 S5). Owner: THR-4.

Cases marked limitation=True are expected to get through: they document what the
gateway cannot see (encrypted archive, oversized object, HTTPS that is not bumped,
fail-open). T5.12/T5.13 stop the icap service and must stay last (spec §7).
"""
from tests.lib.model import Case

HTTP = "http://downloads.lab.test/files/"
HTTPS = "https://downloads.lab.test/files/"
BLOCKED = "BLOCK:malware-content"

CASES = [
    Case(id="T5.1", actor="alice", url=HTTP + "eicar.com", expect=BLOCKED),
    Case(id="T5.2", actor="alice", url=HTTP + "eicar.zip", expect=BLOCKED),
    Case(id="T5.3", actor="alice", url=HTTP + "eicar-nested.zip", expect=BLOCKED),
    Case(id="T5.4", actor="alice", url=HTTP + "eicar-encrypted.zip", expect="ALLOW",
         limitation=True, note="encrypted archive cannot be scanned"),
    Case(id="T5.5", actor="alice", url=HTTP + "eicar-big.zip", expect="ALLOW",
         limitation=True, note="larger than virus_scan.MaxObjectSize"),
    Case(id="T5.6", actor="alice", url=HTTP + "clean.pdf", expect="ALLOW",
         note="no false positive on a clean file"),
    Case(id="T5.7", actor="admin1", url=HTTP + "eicar.com", expect=BLOCKED),
    Case(id="T5.8", actor="guest", url=HTTP + "eicar.com", expect=BLOCKED),
    Case(id="T5.9", actor="alice", url=HTTPS + "eicar.com", expect="ALLOW",
         limitation=True, state={"tls": "splice"}, note="HTTPS not bumped: ICAP sees nothing"),
    Case(id="T5.10", actor="alice", url=HTTPS + "eicar.com", expect=BLOCKED,
         state={"tls": "selective"}),
    Case(id="T5.11", actor="guest", url=HTTPS + "eicar.com", expect="ALLOW",
         limitation=True, state={"tls": "selective"}, note="BYOD traffic is spliced"),
    Case(id="T5.12", actor="alice", url=HTTP + "eicar.com", expect="UPSTREAM_ERROR",
         state={"icap_running": False, "icap_bypass": "off"}, note="fail-closed"),
    # Unique query string: a fail-open response must not stay in the cache, or a
    # later T5.1 would be answered from cache without being scanned.
    Case(id="T5.13", actor="alice", url=HTTP + "eicar.com?failopen={runid}", expect="ALLOW",
         limitation=True, state={"icap_running": False, "icap_bypass": "on"},
         note="fail-open"),
]
