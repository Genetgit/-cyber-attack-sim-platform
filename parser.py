"""Pure, unit-testable parsing of sshd auth-log lines into EVENT dicts.
No I/O here — this module only turns a line of text into data or None."""
import re
import uuid
from datetime import datetime, timezone

FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+ ssh2")
ACCEPTED = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+ ssh2")

def _now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_line(line: str, host_id: str) -> dict | None:
    """Return an EVENT dict for a login attempt line, or None if the line is irrelevant."""
    m = FAILED.search(line)
    if m:
        event_type = "ssh_login_failed"
    else:
        m = ACCEPTED.search(line)
        event_type = "ssh_login_success" if m else None
    if not m:
        return None
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": _now_z(),
        "host_id": host_id,
        "source": "auth_log",
        "event_type": event_type,
        "src_ip": m["ip"],
        "username": m["user"],
        "raw": line.strip(),
    }
