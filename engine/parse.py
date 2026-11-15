"""Log line parser turning raw syslog-style lines into structured event dicts."""

from datetime import datetime
from pathlib import Path
import re
from typing import Any

# Header format: <ISO-8601 timestamp> <host> <program>[optional pid]: <message>
HEADER_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})\s+"
    r"(?P<host>[a-zA-Z0-9._-]+)\s+"
    r"(?P<program>[a-zA-Z0-9._-]+)(?:\[\d+\])?:\s+"
    r"(?P<msg>.+)$"
)

SSH_FAIL_RE = re.compile(
    r"^Failed password for (?:invalid user )?(?P<username>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+) ssh2$"
)

SSH_OK_RE = re.compile(
    r"^Accepted password for (?P<username>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+) ssh2$"
)

SUDO_RE = re.compile(
    r"^(?P<username>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)

UFW_BLOCK_RE = re.compile(
    r"^\[UFW BLOCK\]\s+SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)\s+DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)\s+PROTO=(?P<proto>\S+)\s+DPT=(?P<dpt>\d+)$"
)

LOCKOUT_RE = re.compile(
    r"^user (?P<username>\S+) locked out after too many failures$"
)


def parse_line(raw_line: str) -> dict[str, Any] | None:
    """Parse a single log line into a structured dict, or return None if malformed."""
    if not raw_line or not isinstance(raw_line, str):
        return None
    stripped = raw_line.strip()
    if not stripped:
        return None

    m = HEADER_RE.match(stripped)
    if not m:
        return None

    ts = m.group("ts")
    # Validate ISO timestamp
    try:
        datetime.fromisoformat(ts)
    except ValueError:
        return None

    host = m.group("host")
    program = m.group("program")
    msg = m.group("msg")

    src_ip: str | None = None
    dst_port: int | None = None
    username: str | None = None
    event_type = "other"

    if program == "sshd":
        m_fail = SSH_FAIL_RE.match(msg)
        if m_fail:
            event_type = "ssh_fail"
            username = m_fail.group("username")
            src_ip = m_fail.group("src_ip")
            dst_port = int(m_fail.group("port"))
        else:
            m_ok = SSH_OK_RE.match(msg)
            if m_ok:
                event_type = "ssh_ok"
                username = m_ok.group("username")
                src_ip = m_ok.group("src_ip")
                dst_port = int(m_ok.group("port"))
    elif program == "sudo":
        m_sudo = SUDO_RE.match(msg)
        if m_sudo:
            username = m_sudo.group("username")
            target_user = m_sudo.group("target_user")
            if target_user == "root":
                event_type = "sudo_root"
            else:
                event_type = "other"
    elif program == "kernel":
        m_ufw = UFW_BLOCK_RE.match(msg)
        if m_ufw:
            event_type = "fw_block"
            src_ip = m_ufw.group("src_ip")
            dst_port = int(m_ufw.group("dpt"))
    elif program == "pam_tally2":
        m_lock = LOCKOUT_RE.match(msg)
        if m_lock:
            event_type = "lockout"
            username = m_lock.group("username")

    return {
        "ts": ts,
        "host": host,
        "program": program,
        "raw_line": stripped,
        "src_ip": src_ip,
        "dst_port": dst_port,
        "username": username,
        "event_type": event_type,
    }


def parse_file(log_path: Path | str) -> list[dict[str, Any]]:
    """Parse all valid lines in a log file, skipping malformed lines."""
    path = Path(log_path)
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            parsed = parse_line(line)
            if parsed is not None:
                events.append(parsed)
    return events
