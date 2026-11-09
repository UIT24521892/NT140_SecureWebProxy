#!/usr/bin/env python3
"""Generate harmless lab fixtures at container start (spec §8, TLS-9)."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import zipfile


def make_pdf() -> bytes:
    stream = b"BT /F1 14 Tf 50 750 Td (NT140 clean PDF fixture) Tj ET\n"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"endstream",
    ]
    result = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, content in enumerate(objects, 1):
        offsets.append(len(result))
        result.extend(f"{number} 0 obj\n".encode() + content + b"\nendobj\n")
    xref = len(result)
    result.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        result.extend(f"{offset:010d} 00000 n \n".encode())
    result.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(result)


def generate(root: Path) -> None:
    files = root / "files"
    files.mkdir(parents=True, exist_ok=True)
    page = b"<!doctype html><html><body><h1>NT140 benchmark</h1><!--"
    tail = b"--></body></html>\n"
    (root / "page-1k.html").write_bytes(page + b" " * (1024 - len(page) - len(tail)) + tail)
    # Split deliberately: never put the complete antivirus test string in the repo.
    eicar = b"".join((b"X5O!P%@AP[4", b"\\PZX54(P^)7CC)7}", b"$EICAR-STANDARD-",
                      b"ANTIVIRUS-TEST-FILE!", b"$H+H*"))
    assert len(eicar) == 68
    (files / "eicar.com").write_bytes(eicar)
    (files / "clean.pdf").write_bytes(make_pdf())
    pe = b"MZ\x00\x00NT140 harmless fixture; not an executable program.\n"
    for name in ("setup.exe", "invoice.pdf.exe", "renamed-exe.txt"):
        (files / name).write_bytes(pe)
    with zipfile.ZipFile(files / "app.apk", "w") as archive:
        archive.writestr("README.txt", "NT140 fixture, not an Android application.\n")
    with zipfile.ZipFile(files / "eicar.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("eicar.com", eicar)
    with zipfile.ZipFile(files / "eicar-nested.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(files / "eicar.zip", "eicar.zip")
    with zipfile.ZipFile(files / "eicar-big.zip", "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("eicar.com", eicar)
        archive.writestr("padding.bin", os.urandom(12 * 1024 * 1024))
    encrypted = files / "eicar-encrypted.zip"
    encrypted.unlink(missing_ok=True)
    subprocess.run(["zip", "-q", "-j", "-P", "infected", str(encrypted.resolve()),
                    str((files / "eicar.com").resolve())], check=True)
    for size in (1, 2, 10):
        path = root / f"{size}m.bin"
        if not path.exists():
            path.write_bytes(os.urandom(size * 1024 * 1024))
    for name in ("1m-nocache.bin", "payload.bin"):
        path = root / name
        if not path.exists():
            path.write_bytes(os.urandom(1024 * 1024))
    print("testweb: generated lab fixtures")


if __name__ == "__main__":
    generate(Path(sys.argv[1] if len(sys.argv) > 1 else "/srv/data"))
