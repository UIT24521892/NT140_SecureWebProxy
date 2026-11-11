"""S9 hardening acceptance data (TLS-5). Policy belongs to POL-3."""
CASES = [
    dict(id="T9.1", actor="alice", url="http://allowed.lab.test/", options=["--direct"], expect="CONN_FAIL"),
    dict(id="T9.2", actor="alice", url="https://1.1.1.1/", options=["--direct"], expect="CONN_FAIL"),
    dict(id="T9.3", actor="alice", url="https://allowed.lab.test:8443/", expect="BLOCK", reason="default"),
    dict(id="T9.4", actor="alice", url="http://172.30.0.50/", expect="BLOCK", reason="ip-literal"),
    dict(id="T9.5", actor="admin1", url="http://172.30.0.50/", expect="ALLOW"),
    dict(id="T9.6", actor="alice", url="https://dns.lab.test/dns-query?name=example.com", expect="BLOCK", reason="doh"),
    dict(id="T9.7", actor="alice", url="https://cloudflare-dns.com/dns-query", expect="BLOCK", reason="doh", requires_policy=True),
    dict(id="T9.8", kind="cmd", service="client-staff", command=["python3", "-c", "import socket; socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'lab',(\"1.1.1.1\",443))"], nonzero=True, contains="Network is unreachable"),
]
DEFAULT_STATE = dict(tls="selective", worktime="never")
for case in CASES:
    case.setdefault("kind", "probe")
    case.setdefault("priority", "P1")
