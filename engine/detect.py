"""Detection rules R1 (T1110 Brute Force), R2 (T1046 Port Scan), and R3 (T1548 Privilege Escalation)."""

from datetime import datetime
import json
import logging
from pathlib import Path
import sqlite3
from typing import Any

from engine.db import load_assets_by_hostname

logger = logging.getLogger(__name__)

ALLOWED_ADMINS = {"admin", "sysadmin"}


def _parse_ts(ts_str: str) -> datetime:
    return datetime.fromisoformat(ts_str)


def _merge_intervals(intervals: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Merge overlapping or index-adjacent intervals [start_idx, end_idx]."""
    if not intervals:
        return []
    sorted_iv = sorted(intervals, key=lambda x: (x[0], x[1]))
    merged: list[tuple[int, int]] = [sorted_iv[0]]
    for start, end in sorted_iv[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def detect_events(
    events: list[dict[str, Any]],
    assets_by_host: dict[str, dict[str, Any]] | None = None,
    data_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Run pure detection rules R1, R2, R3 over structured log events.

    Each input event may optionally have an 'id' key (defaults to its 1-based position).
    Unknown hosts not in assets.csv are ignored and logged.
    """
    host_map = assets_by_host if assets_by_host is not None else load_assets_by_hostname(data_dir)

    valid_events: list[dict[str, Any]] = []
    for idx, ev in enumerate(events, start=1):
        host = ev.get("host", "")
        if host not in host_map:
            logger.warning("Ignoring event from unknown host: %s", host)
            continue
        ev_copy = dict(ev)
        if "id" not in ev_copy or ev_copy["id"] is None:
            ev_copy["id"] = idx
        valid_events.append(ev_copy)

    raw_detections: list[dict[str, Any]] = []

    # --- R1: Brute force (T1110) ---
    # 5 or more Failed password events from same src_ip to same host within any 120s sliding window
    ssh_fails_by_group: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for ev in valid_events:
        if ev.get("event_type") == "ssh_fail" and ev.get("src_ip"):
            key = (ev["host"], ev["src_ip"])
            ssh_fails_by_group.setdefault(key, []).append(ev)

    for (host, src_ip), group in ssh_fails_by_group.items():
        group_sorted = sorted(group, key=lambda e: (_parse_ts(e["ts"]), e["id"]))
        qualifying_windows: list[tuple[int, int]] = []
        n = len(group_sorted)
        for i in range(n):
            t_start = _parse_ts(group_sorted[i]["ts"])
            j = i
            while j + 1 < n and (_parse_ts(group_sorted[j + 1]["ts"]) - t_start).total_seconds() <= 120:
                j += 1
            window_count = j - i + 1
            if window_count >= 5:
                qualifying_windows.append((i, j))

        for start_idx, end_idx in _merge_intervals(qualifying_windows):
            burst = group_sorted[start_idx : end_idx + 1]
            ev_ids = [int(e["id"]) for e in burst]
            first_seen = burst[0]["ts"]
            last_seen = burst[-1]["ts"]
            count = len(burst)
            duration_s = int((_parse_ts(last_seen) - _parse_ts(first_seen)).total_seconds())
            raw_detections.append(
                {
                    "threat_id": "T1110",
                    "host": host,
                    "asset_id": host_map[host]["asset_id"],
                    "source": src_ip,
                    "event_count": count,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "evidence_event_ids": ev_ids,
                    "details": f"{count} failed logins from IP {src_ip} to {host} within {duration_s} seconds",
                }
            )

    # --- R2: Port scan (T1046) ---
    # 10 or more distinct DPT values from same SRC to same host within any 60s sliding window
    fw_by_group: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for ev in valid_events:
        if ev.get("event_type") == "fw_block" and ev.get("src_ip") and ev.get("dst_port") is not None:
            key = (ev["host"], ev["src_ip"])
            fw_by_group.setdefault(key, []).append(ev)

    for (host, src_ip), group in fw_by_group.items():
        group_sorted = sorted(group, key=lambda e: (_parse_ts(e["ts"]), e["id"]))
        qualifying_windows = []
        n = len(group_sorted)
        for i in range(n):
            t_start = _parse_ts(group_sorted[i]["ts"])
            j = i
            while j + 1 < n and (_parse_ts(group_sorted[j + 1]["ts"]) - t_start).total_seconds() <= 60:
                j += 1
            distinct_ports_in_win = {
                int(group_sorted[k]["dst_port"]) for k in range(i, j + 1)
            }
            if len(distinct_ports_in_win) >= 10:
                qualifying_windows.append((i, j))

        for start_idx, end_idx in _merge_intervals(qualifying_windows):
            burst = group_sorted[start_idx : end_idx + 1]
            ev_ids = [int(e["id"]) for e in burst]
            distinct_ports = sorted({int(e["dst_port"]) for e in burst})
            first_seen = burst[0]["ts"]
            last_seen = burst[-1]["ts"]
            count = len(distinct_ports)
            duration_s = int((_parse_ts(last_seen) - _parse_ts(first_seen)).total_seconds())
            raw_detections.append(
                {
                    "threat_id": "T1046",
                    "host": host,
                    "asset_id": host_map[host]["asset_id"],
                    "source": src_ip,
                    "event_count": count,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "evidence_event_ids": ev_ids,
                    "details": f"{count} distinct ports scanned from IP {src_ip} on {host} within {duration_s} seconds (blocked by UFW)",
                }
            )

    # --- R3: Privilege escalation (T1548) ---
    # Any sudo line with USER=root where invoking account is not in {admin, sysadmin}
    for ev in valid_events:
        if ev.get("event_type") == "sudo_root":
            user = ev.get("username") or ""
            if user not in ALLOWED_ADMINS:
                host = ev["host"]
                raw_detections.append(
                    {
                        "threat_id": "T1548",
                        "host": host,
                        "asset_id": host_map[host]["asset_id"],
                        "source": user,
                        "event_count": 1,
                        "first_seen": ev["ts"],
                        "last_seen": ev["ts"],
                        "evidence_event_ids": [int(ev["id"])],
                        "details": f"Non-admin user '{user}' elevated to root via sudo on {host}",
                    }
                )

    # Sort deterministically by first_seen ascending, then threat_id, then host
    raw_detections.sort(key=lambda d: (_parse_ts(d["first_seen"]), d["threat_id"], d["host"]))

    detections: list[dict[str, Any]] = []
    for idx, det in enumerate(raw_detections, start=1):
        det_with_id = {
            "detection_id": idx,
            "threat_id": det["threat_id"],
            "host": det["host"],
            "asset_id": det["asset_id"],
            "source": det["source"],
            "event_count": det["event_count"],
            "first_seen": det["first_seen"],
            "last_seen": det["last_seen"],
            "evidence_event_ids": det["evidence_event_ids"],
            "details": det["details"],
        }
        detections.append(det_with_id)

    return detections


def run_detections_on_db(conn: sqlite3.Connection, data_dir: Path | None = None) -> list[dict[str, Any]]:
    """Load log_events from SQLite, run detection rules, store in detections table, and return them."""
    rows = conn.execute(
        "SELECT id, ts, host, program, raw_line, src_ip, dst_port, username, event_type FROM log_events ORDER BY id ASC"
    ).fetchall()
    events = [dict(r) for r in rows]
    detections = detect_events(events, data_dir=data_dir)

    conn.execute("DELETE FROM detections")
    for d in detections:
        details_payload = json.dumps(
            {
                "summary": d["details"],
                "evidence_event_ids": d["evidence_event_ids"],
            }
        )
        conn.execute(
            """
            INSERT INTO detections(
                detection_id, threat_id, host, asset_id, source, event_count, first_seen, last_seen, details
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                d["detection_id"],
                d["threat_id"],
                d["host"],
                d["asset_id"],
                d["source"],
                d["event_count"],
                d["first_seen"],
                d["last_seen"],
                details_payload,
            ),
        )
    conn.commit()
    return detections
