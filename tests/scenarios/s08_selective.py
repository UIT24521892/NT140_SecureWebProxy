"""S8 acceptance data, including expected TLS limitations (TLS-4)."""
CASES = [
    dict(id="T8.1", actor="alice", url="https://allowed.lab.test/", expect="ALLOW", expect_issuer="NT140 SWG Proxy CA"),
    dict(id="T8.2", actor="alice", url="https://allowed.lab.test/upload", expect="BLOCK", reason="path"),
    dict(id="T8.3", actor="alice", url="https://uitbank.lab.test/", expect="ALLOW", expect_issuer="NT140 Lab Public Root CA"),
    dict(id="T8.4", actor="guest", url="https://allowed.lab.test/", expect="ALLOW", expect_issuer="NT140 Lab Public Root CA"),
    dict(id="T8.5", actor="alice", url="https://pinned.lab.test/", options=["--pinned"], expect="TLS_ERROR", limitation=True),
    dict(id="T8.6", actor="alice-unmanaged", url="https://allowed.lab.test/", expect="TLS_ERROR"),
    dict(id="T8.7", kind="repeat", actor="alice", url="https://cache.lab.test/cacheable/{runid}/1m.bin", hit=True),
    dict(id="T8.8", kind="logcheck", source="T8.1", fields=dict(method="GET", url="https://allowed.lab.test/", bump_mode="bump")),
    dict(id="T8.9", actor="guest", url="https://allowed.lab.test/", state=dict(tls="bump"), expect="TLS_ERROR"),
]
DEFAULT_STATE = dict(tls="selective", worktime="never")
for case in CASES:
    case.setdefault("kind", "probe")
    case.setdefault("priority", "P0")

# Shared acceptance checks requested from TV2 by TV1 (TLS-4).
SUPPORT_CASES = [
    dict(id="T1.5", actor="guest", kind="probe", url="https://social.lab.test/", expect="BLOCK", reason="social", priority="P0"),
    dict(id="T6.7", actor="alice", kind="probe", url="https://downloads.lab.test/files/setup.exe", expect="ALLOW", limitation=True, state=dict(tls="splice"), priority="P1"),
    dict(id="T6.8", actor="alice", kind="probe", url="https://downloads.lab.test/files/setup.exe", expect="BLOCK", reason="filetype", priority="P1"),
]
