"""S7 acceptance data (TLS-4). Dictionaries map directly to spec §11 Case fields."""
CASES = [
    dict(id="T7.1", actor="alice", url="https://social.lab.test/", expect="BLOCK", reason="worktime", state=dict(tls="splice", worktime="always")),
    dict(id="T7.2", actor="alice", url="http://allowed.lab.test/upload", expect="BLOCK", reason="path"),
    dict(id="T7.3", actor="alice", url="https://allowed.lab.test/upload", expect="ALLOW", limitation=True),
    dict(id="T7.4", actor="alice", url="https://allowed.lab.test/", expect="ALLOW", expect_issuer="NT140 Lab Public Root CA"),
    dict(id="T7.5", kind="logcheck", source="T7.4", fields=dict(method="CONNECT", url="allowed.lab.test:443", result="TCP_TUNNEL", bump_mode="splice")),
    dict(id="T7.6", kind="sni_probe", actor="alice", host="allowed.lab.test", sni="uitbank-secure-login.lab.test", expect="TLS_ERROR", policy="sni-threat"),
    dict(id="T7.7", actor="alice", url="https://pinned.lab.test/", options=["--pinned"], expect="ALLOW"),
    dict(id="T7.8", kind="repeat", actor="alice", url="https://cache.lab.test/cacheable/{runid}/1m.bin", hit=False, limitation=True),
]
DEFAULT_STATE = dict(tls="splice", worktime="never")
for case in CASES:
    case.setdefault("kind", "probe")
    case.setdefault("priority", "P0")
