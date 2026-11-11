"""S6: blocking by file type (spec §13 S6, P1). Owner: POL-6."""
from tests.lib.model import Case

HTTP = "http://downloads.lab.test"
HTTPS = "https://downloads.lab.test"

CASES = [
    Case(id="T6.1", actor="alice", url=HTTP + "/files/setup.exe", expect="BLOCK:filetype"),
    Case(id="T6.2", actor="alice", url=HTTP + "/files/invoice.pdf.exe", expect="BLOCK:filetype"),
    Case(id="T6.3", actor="alice", url=HTTP + "/dl/a1b2c3", expect="BLOCK:filetype-mime",
         note="no extension in the URL, caught by the response MIME type"),
    Case(id="T6.4", actor="alice", url=HTTP + "/files/renamed-exe.txt", expect="ALLOW",
         limitation=True, note="magic bytes are not inspected"),
    Case(id="T6.5", actor="admin1", url=HTTP + "/files/setup.exe", expect="ALLOW"),
    Case(id="T6.6", actor="guest", url=HTTP + "/files/app.apk", expect="BLOCK:filetype"),
    Case(id="T6.7", actor="alice", url=HTTPS + "/files/setup.exe", expect="ALLOW",
         limitation=True, state={"tls": "splice"}, note="path is not visible when spliced"),
    Case(id="T6.8", actor="alice", url=HTTPS + "/files/setup.exe", expect="BLOCK:filetype",
         state={"tls": "selective"}),
]
for _case in CASES:
    _case.priority = "P1"
