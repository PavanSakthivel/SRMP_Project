"""Tests for engine/parse.py covering all six line formats in Section 4.1 and malformed lines."""

from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from engine.parse import parse_file, parse_line


def test_parse_all_six_section_4_1_formats():
    l1 = "2026-11-10T09:15:02+05:30 pay-srv-01 sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 51234 ssh2"
    p1 = parse_line(l1)
    assert p1 is not None
    assert p1["ts"] == "2026-11-10T09:15:02+05:30"
    assert p1["host"] == "pay-srv-01"
    assert p1["program"] == "sshd"
    assert p1["event_type"] == "ssh_fail"
    assert p1["username"] == "admin"
    assert p1["src_ip"] == "203.0.113.45"
    assert p1["dst_port"] == 51234

    l2 = "2026-11-10T09:15:40+05:30 pay-srv-01 sshd[1234]: Failed password for root from 203.0.113.45 port 51240 ssh2"
    p2 = parse_line(l2)
    assert p2 is not None
    assert p2["event_type"] == "ssh_fail"
    assert p2["username"] == "root"
    assert p2["src_ip"] == "203.0.113.45"
    assert p2["dst_port"] == 51240

    l3 = "2026-11-10T09:30:11+05:30 db-srv-01 sshd[2201]: Accepted password for admin from 10.0.0.15 port 40022 ssh2"
    p3 = parse_line(l3)
    assert p3 is not None
    assert p3["host"] == "db-srv-01"
    assert p3["event_type"] == "ssh_ok"
    assert p3["username"] == "admin"
    assert p3["src_ip"] == "10.0.0.15"
    assert p3["dst_port"] == 40022

    l4 = "2026-11-10T10:05:33+05:30 db-srv-01 sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash"
    p4 = parse_line(l4)
    assert p4 is not None
    assert p4["host"] == "db-srv-01"
    assert p4["program"] == "sudo"
    assert p4["event_type"] == "sudo_root"
    assert p4["username"] == "bob"
    assert p4["src_ip"] is None
    assert p4["dst_port"] is None

    l5 = "2026-11-10T09:20:01+05:30 exam-srv-01 kernel: [UFW BLOCK] SRC=198.51.100.7 DST=10.0.0.5 PROTO=TCP DPT=22"
    p5 = parse_line(l5)
    assert p5 is not None
    assert p5["host"] == "exam-srv-01"
    assert p5["program"] == "kernel"
    assert p5["event_type"] == "fw_block"
    assert p5["src_ip"] == "198.51.100.7"
    assert p5["dst_port"] == 22

    l6 = "2026-11-10T09:16:30+05:30 pay-srv-01 pam_tally2[1300]: user root locked out after too many failures"
    p6 = parse_line(l6)
    assert p6 is not None
    assert p6["host"] == "pay-srv-01"
    assert p6["program"] == "pam_tally2"
    assert p6["event_type"] == "lockout"
    assert p6["username"] == "root"


def test_malformed_lines_skipped_without_crashing(tmp_path: Path):
    assert parse_line("") is None
    assert parse_line("   ") is None
    assert parse_line("not a valid syslog line at all") is None
    assert parse_line("2026-99-99T99:99:99+05:30 db-srv-01 sshd[1]: Failed password") is None

    mixed_file = tmp_path / "mixed.log"
    mixed_file.write_text(
        "corrupted line 1\n"
        "2026-11-10T09:30:11+05:30 db-srv-01 sshd[2201]: Accepted password for admin from 10.0.0.15 port 40022 ssh2\n"
        "   \n"
        "bad_timestamp host prog: message\n",
        encoding="utf-8",
    )
    parsed = parse_file(mixed_file)
    assert len(parsed) == 1
    assert parsed[0]["event_type"] == "ssh_ok"
