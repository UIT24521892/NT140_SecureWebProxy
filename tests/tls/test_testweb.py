"""Run on the Docker WAN to validate actual nginx payloads and MIME (TLS-9)."""
from __future__ import annotations

from io import BytesIO
import json
import ssl
import unittest
from urllib.request import build_opener, ProxyHandler, HTTPSHandler
import zipfile


class TestwebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.opener = build_opener(ProxyHandler({}), HTTPSHandler(
            context=ssl.create_default_context(cafile="/opt/certs/lab-public-ca.crt")))

    def fetch(self, path: str, host: str = "downloads.lab.test", scheme: str = "http") -> tuple[bytes, dict]:
        with self.opener.open(f"{scheme}://{host}{path}", timeout=15) as response:
            self.assertEqual(response.status, 200)
            return response.read(), response.headers

    def test_aliases_and_https(self) -> None:
        for host in ("allowed", "social", "games", "stream", "gamble", "uitbank",
                     "uitbank-secure-login", "uitbank-verify-account", "malware-cdn",
                     "downloads", "cache", "pinned", "dns"):
            domain = host + ".lab.test"
            with self.subTest(host=domain):
                body, _ = self.fetch("/", domain, "https")
                self.assertIn(f"LAB-ORIGIN host={domain}".encode(), body)

    def test_content_types_and_disposition(self) -> None:
        types = {"clean.pdf": "application/pdf", "eicar.com": "application/octet-stream",
                 "eicar.zip": "application/zip", "eicar-nested.zip": "application/zip",
                 "eicar-encrypted.zip": "application/zip", "eicar-big.zip": "application/zip",
                 "setup.exe": "application/x-msdownload", "invoice.pdf.exe": "application/x-msdownload",
                 "renamed-exe.txt": "text/plain", "app.apk": "application/vnd.android.package-archive"}
        for name, content_type in types.items():
            with self.subTest(path=name):
                _, headers = self.fetch("/files/" + name)
                self.assertEqual(headers.get_content_type(), content_type)
        body, headers = self.fetch("/dl/a1b2c3")
        self.assertTrue(body.startswith(b"MZ"))
        self.assertEqual(headers.get_content_type(), "application/x-msdownload")
        self.assertIn('filename="update.exe"', headers["Content-Disposition"])

    def test_archives_and_pdf(self) -> None:
        eicar, _ = self.fetch("/files/eicar.com")
        self.assertEqual(len(eicar), 68)
        for path in ("eicar.zip", "eicar-encrypted.zip", "eicar-big.zip"):
            body, _ = self.fetch("/files/" + path)
            with zipfile.ZipFile(BytesIO(body)) as archive:
                self.assertEqual(archive.read("eicar.com", pwd=b"infected"), eicar)
                if "encrypted" in path:
                    self.assertTrue(archive.getinfo("eicar.com").flag_bits & 1)
                if "big" in path:
                    self.assertGreater(len(body), 10 * 1024 * 1024)
        body, _ = self.fetch("/files/eicar-nested.zip")
        with zipfile.ZipFile(BytesIO(body)) as outer:
            with zipfile.ZipFile(BytesIO(outer.read("eicar.zip"))) as inner:
                self.assertEqual(inner.read("eicar.com"), eicar)
        pdf, _ = self.fetch("/files/clean.pdf")
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        offset = int(pdf.split(b"startxref\n")[1].splitlines()[0])
        self.assertTrue(pdf[offset:].startswith(b"xref"))

    def test_cache_paths(self) -> None:
        page, _ = self.fetch("/bench/unique/page/", "cache.lab.test")
        self.assertEqual(len(page), 1024)
        first, headers = self.fetch("/cacheable/test-one/1m.bin", "cache.lab.test")
        second, _ = self.fetch("/cacheable/test-two/1m.bin", "cache.lab.test")
        self.assertEqual(len(first), 1024 * 1024)
        self.assertEqual(first, second)
        self.assertIn("max-age=3600", headers["Cache-Control"])
        self.assertIn("ETag", headers)
        self.assertIn("Last-Modified", headers)
        _, headers = self.fetch("/nocache/1m.bin", "cache.lab.test")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_demo_endpoints(self) -> None:
        body, _ = self.fetch("/login", "uitbank-secure-login.lab.test")
        self.assertIn(b"UIT Bank", body)
        self.assertIn(b'action="#"', body)
        body, _ = self.fetch("/upload", "allowed.lab.test")
        self.assertIn(b"<form", body)
        body, _ = self.fetch("/dns-query", "dns.lab.test")
        self.assertEqual(json.loads(body)["Status"], 0)
        body, _ = self.fetch("/payload.bin", "malware-cdn.lab.test")
        self.assertGreater(len(body), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
