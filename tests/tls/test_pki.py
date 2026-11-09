"""Verify PKI idempotence, forced rotation and failure on mismatched keys."""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "scripts/gen-certs.sh"


class PKITests(unittest.TestCase):
    def test_generation_idempotence_rotation_and_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "scripts").mkdir()
            shutil.copyfile(SOURCE, root / "scripts/gen-certs.sh")

            def generate(*args: str, check: bool = True) -> subprocess.CompletedProcess:
                return subprocess.run(["bash", str(root / "scripts/gen-certs.sh"), *args],
                                      cwd=root, capture_output=True, text=True, check=check)

            def hashes() -> dict:
                return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in (root / "certs").iterdir()}

            generate()
            first = hashes()
            generate()
            self.assertEqual(first, hashes())
            for ca in ("lab-public-ca", "lab-proxy-ca"):
                result = subprocess.run(["openssl", "x509", "-in", str(root / f"certs/{ca}.crt"),
                                         "-text", "-noout"], capture_output=True, text=True, check=True)
                self.assertIn("CA:TRUE", result.stdout)
            generate("--force")
            self.assertNotEqual(first["lab-public-ca.crt"], hashes()["lab-public-ca.crt"])
            self.assertNotEqual(first["pinned.sha256"], hashes()["pinned.sha256"])
            shutil.copyfile(root / "certs/lab-proxy-ca.key", root / "certs/lab-public-ca.key")
            result = generate(check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("key mismatch", result.stderr)

    def test_invalid_option_fails(self) -> None:
        result = subprocess.run(["bash", str(SOURCE), "--unknown"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
