"""S2: policy by user, group and time (spec §13 S2). Owner: POL-6."""
from tests.lib.model import Case

IN_HOURS = {"worktime": "always"}

CASES = [
    Case(id="T2.1", actor="badpass", url="http://allowed.lab.test/", expect="AUTH_REQUIRED"),
    Case(id="T2.2", actor="alice", url="http://allowed.lab.test/", expect="ALLOW"),
    Case(id="T2.3", kind="logcheck", source="T2.2", fields={"user": "alice"}),
    Case(id="T2.4", actor="alice", url="http://social.lab.test/", expect="BLOCK:worktime",
         state=IN_HOURS),
    Case(id="T2.5", actor="alice", url="https://social.lab.test/", expect="BLOCK:worktime",
         state=IN_HOURS),
    Case(id="T2.6", actor="bob", url="http://games.lab.test/", expect="BLOCK:worktime",
         state=IN_HOURS),
    Case(id="T2.7", actor="admin1", url="http://social.lab.test/", expect="ALLOW",
         state=IN_HOURS),
    Case(id="T2.8", actor="alice", url="http://social.lab.test/", expect="ALLOW",
         state={"worktime": "never"}),
    Case(id="T2.9", actor="alice", url="http://gamble.lab.test/", expect="BLOCK:gambling"),
    Case(id="T2.10", actor="admin1", url="http://gamble.lab.test/", expect="ALLOW"),
]
