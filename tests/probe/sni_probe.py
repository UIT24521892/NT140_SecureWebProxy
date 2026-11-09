"""Use a CONNECT hostname different from TLS SNI, preserving X-Lab-Test-Id."""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import sys
from urllib.parse import urlsplit


def main() -> int:
    host, sni, test_id = sys.argv[1:4]
    proxy = urlsplit(os.environ["PROXY_URL"])
    with socket.create_connection((proxy.hostname, proxy.port or 3128), timeout=10) as connection:
        request = [f"CONNECT {host}:443 HTTP/1.1", f"Host: {host}:443", f"X-Lab-Test-Id: {test_id}"]
        credential = os.environ.get("LAB_PROXY_CREDENTIAL")
        if credential:
            request.append("Proxy-Authorization: Basic " + base64.b64encode(credential.encode()).decode())
        connection.sendall(("\r\n".join(request) + "\r\n\r\n").encode("ascii"))
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            part = connection.recv(1)
            if not part or len(header) > 65536:
                raise RuntimeError("invalid CONNECT response")
            header.extend(part)
        code = int(bytes(header).split(b" ", 2)[1])
        if code != 200:
            print(json.dumps(dict(outcome="AUTH_REQUIRED" if code == 407 else "UPSTREAM_ERROR", connect_code=code)))
            return 0
        try:
            with ssl.create_default_context().wrap_socket(connection, server_hostname=sni):
                print(json.dumps(dict(outcome="ALLOW", connect_code=code)))
        except (ssl.SSLError, ConnectionResetError):
            print(json.dumps(dict(outcome="TLS_ERROR", connect_code=code)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
