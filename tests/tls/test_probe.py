"""Exercise the real Bash/curl/JSON boundary against a local deterministic proxy."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import unittest

PROBE = Path(__file__).resolve().parents[1] / "probe/probe.sh"


class Proxy(BaseHTTPRequestHandler):
    def log_message(self, *_: object) -> None:
        pass

    def do_GET(self) -> None:
        if self.headers.get_all("X-Lab-Test-Id") != ["boundary-test"]:
            code, body = 500, b"missing or duplicated test header"
        elif self.path.endswith("/auth"):
            code, body = 407, b"authentication required"
        elif self.path.endswith("/block"):
            code, body = 403, b"<!-- LAB-BLOCK reason=worktime -->"
        elif self.path.endswith("/upstream"):
            code, body = 503, b"upstream unavailable"
        else:
            code, body = 200, b"<!-- LAB-ORIGIN host=origin.lab.test -->"
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        if code == 407:
            self.send_header("Proxy-Authenticate", 'Basic realm="NT140 test"')
        self.end_headers()
        self.wfile.write(body)

    def do_CONNECT(self) -> None:
        self.send_response(403)
        self.send_header("X-Squid-Error", "ERR_LAB_SOCIAL 0")
        self.send_header("Content-Length", "0")
        self.end_headers()


class ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join()

    def invoke(self, url: str, *options: str) -> dict:
        env = dict(os.environ, PROXY_URL=f"http://127.0.0.1:{self.port}", NO_PROXY="*")
        result = subprocess.run(["bash", str(PROBE), "-t", "boundary-test", "--max-time", "2", *options, url],
                                env=env, capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertEqual(result.stderr, "")
        record = json.loads(result.stdout)
        self.assertEqual(record["test_id"], "boundary-test")
        return record

    def test_allow_even_when_no_proxy_environment_is_set(self) -> None:
        result = self.invoke("http://origin.lab.test/allow")
        self.assertEqual(result["outcome"], "ALLOW")
        self.assertEqual(result["http_code"], 200)

    def test_auth_required(self) -> None:
        self.assertEqual(self.invoke("http://origin.lab.test/auth")["outcome"], "AUTH_REQUIRED")

    def test_block_marker(self) -> None:
        result = self.invoke("http://origin.lab.test/block")
        self.assertEqual((result["outcome"], result["reason"]), ("BLOCK", "worktime"))

    def test_connect_deny_header(self) -> None:
        result = self.invoke("https://origin.lab.test/")
        self.assertEqual((result["outcome"], result["reason"], result["connect_code"]), ("BLOCK", "social", 403))

    def test_upstream_error(self) -> None:
        self.assertEqual(self.invoke("http://origin.lab.test/upstream")["outcome"], "UPSTREAM_ERROR")

    def test_tls_error(self) -> None:
        self.assertEqual(self.invoke(f"https://127.0.0.1:{self.port}/", "--direct")["outcome"], "TLS_ERROR")

    def test_connection_failure(self) -> None:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.assertEqual(self.invoke(f"http://127.0.0.1:{port}/", "--direct")["outcome"], "CONN_FAIL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
