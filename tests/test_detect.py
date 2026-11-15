"""Tests for engine/detect.py verifying sample log detections, benign noise, and admin sudo exclusion."""

from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from engine.db import DATA_DIR
from engine.detect import detect_events
from engine.parse import parse_file, parse_line


def test_sample_log_yields_exact_six_detections():
    events = parse_file(DATA_DIR / "sample" / "auth.log")
    detections = detect_events(events)
    assert len(detections) == 6

    expected = [
        ("A4", "ws-lab-01", "T1548", 1),
        ("A1", "db-srv-01", "T1548", 1),
        ("A6", "gw-01", "T1110", 40),
        ("A2", "pay-srv-01", "T1110", 12),
        ("A6", "gw-01", "T1046", 15),
        ("A5", "exam-srv-01", "T1046", 15),
    ]
    for det, (exp_asset, exp_host, exp_threat, exp_count) in zip(detections, expected):
        assert det["asset_id"] == exp_asset
        assert det["host"] == exp_host
        assert det["threat_id"] == exp_threat
        assert det["event_count"] == exp_count


def test_noise_and_admin_sudo_yield_zero_detections():
    noise_lines = [
        # Allowed admin and sysadmin sudo commands
        "2026-11-10T08:20:05+05:30 db-srv-01 sudo: admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash",
        "2026-11-10T08:48:30+05:30 pay-srv-01 sudo: sysadmin : TTY=pts/1 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/usr/bin/apt update",
        # Normal accepted SSH logins
        "2026-11-10T09:00:01+05:30 db-srv-01 sshd[100]: Accepted password for admin from 10.0.0.15 port 40100 ssh2",
        # 3 isolated failed logins (< 5 in 120s)
        "2026-11-10T09:10:01+05:30 web-srv-01 sshd[101]: Failed password for invalid user admin from 192.0.2.10 port 50001 ssh2",
        "2026-11-10T09:10:20+05:30 web-srv-01 sshd[101]: Failed password for invalid user admin from 192.0.2.10 port 50002 ssh2",
        "2026-11-10T09:10:40+05:30 web-srv-01 sshd[101]: Failed password for invalid user admin from 192.0.2.10 port 50003 ssh2",
        # 5 isolated firewall blocks (< 10 distinct ports in 60s)
        "2026-11-10T09:20:01+05:30 web-srv-01 kernel: [UFW BLOCK] SRC=192.0.2.50 DST=10.0.0.3 PROTO=TCP DPT=22",
        "2026-11-10T09:20:05+05:30 web-srv-01 kernel: [UFW BLOCK] SRC=192.0.2.50 DST=10.0.0.3 PROTO=TCP DPT=80",
        "2026-11-10T09:20:10+05:30 web-srv-01 kernel: [UFW BLOCK] SRC=192.0.2.50 DST=10.0.0.3 PROTO=TCP DPT=443",
        "2026-11-10T09:20:15+05:30 web-srv-01 kernel: [UFW BLOCK] SRC=192.0.2.50 DST=10.0.0.3 PROTO=TCP DPT=8080",
        "2026-11-10T09:20:20+05:30 web-srv-01 kernel: [UFW BLOCK] SRC=192.0.2.50 DST=10.0.0.3 PROTO=TCP DPT=8443",
    ]
    parsed = [parse_line(line) for line in noise_lines]
    events = [p for p in parsed if p is not None]
    detections = detect_events(events)
    assert detections == []
