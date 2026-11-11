"""S1: policy by network (spec §13 S1). Owner: POL-6."""
from tests.lib.model import Case

CASES = [
    Case(id="T1.1", actor="guest", url="http://allowed.lab.test/", expect="ALLOW"),
    Case(id="T1.2", actor="guest", url="http://social.lab.test/", expect="BLOCK:social"),
    Case(id="T1.3", actor="guest", url="http://games.lab.test/", expect="BLOCK:games"),
    Case(id="T1.4", actor="guest", url="http://stream.lab.test/", expect="BLOCK:streaming"),
    Case(id="T1.5", actor="guest", url="https://social.lab.test/", expect="BLOCK:social",
         note="blocked at CONNECT"),
    Case(id="T1.6", actor="guest", url="http://gamble.lab.test/", expect="BLOCK:gambling"),
    Case(id="T1.7", actor="alice", url="http://social.lab.test/", expect="ALLOW",
         note="staff outside work hours"),
    Case(id="T1.8", actor="anon", url="http://allowed.lab.test/", expect="AUTH_REQUIRED",
         note="staff network requires authentication, guest network does not"),
]
