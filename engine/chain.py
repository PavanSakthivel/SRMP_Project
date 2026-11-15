"""Tamper-evident SHA-256 log hash chain, verification, and external file anchoring."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from engine.db import ANCHOR_DIR

GENESIS_HASH = "0" * 64


def compute_event_hash(prev_hash: str, timestamp: str, host: str, raw_line: str) -> str:
    """Compute SHA-256 hex digest for a single log event row."""
    payload = f"{prev_hash}|{timestamp}|{host}|{raw_line}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def write_anchor(head_hash: str, row_count: int, anchor_dir: Path | None = None) -> dict[str, Any]:
    """Write the chain head and row count to anchor/head.txt and append to anchor/head_history.log."""
    target_dir = Path(anchor_dir) if anchor_dir is not None else ANCHOR_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    head_data = {
        "head_hash": head_hash,
        "row_count": row_count,
        "anchored_at": now_iso,
    }
    head_file = target_dir / "head.txt"
    head_file.write_text(json.dumps(head_data, indent=2) + "\n", encoding="utf-8")

    history_file = target_dir / "head_history.log"
    with history_file.open("a", encoding="utf-8") as f:
        f.write(f"{now_iso} count={row_count} head={head_hash}\n")

    return head_data


def read_anchor(anchor_dir: Path | None = None) -> dict[str, Any] | None:
    """Read anchor/head.txt if present; return None if missing or invalid."""
    target_dir = Path(anchor_dir) if anchor_dir is not None else ANCHOR_DIR
    head_file = target_dir / "head.txt"
    if not head_file.exists():
        return None
    try:
        return json.loads(head_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def verify_chain(conn: sqlite3.Connection, anchor_dir: Path | None = None) -> dict[str, Any]:
    """Recompute the full SHA-256 chain over log_events and compare against anchor/head.txt.

    Returns:
        {ok: bool, checked: int, first_broken_id: int|None, reason: str, head_hash: str, anchor: dict|None}
    """
    rows = conn.execute(
        "SELECT id, ts, host, raw_line, prev_hash, hash FROM log_events ORDER BY id ASC"
    ).fetchall()

    expected_prev = GENESIS_HASH
    expected_id = 1
    checked = 0

    for row in rows:
        row_id = int(row["id"])
        ts = row["ts"]
        host = row["host"]
        raw_line = row["raw_line"]
        stored_prev = row["prev_hash"]
        stored_hash = row["hash"]

        # Check for deleted row (gap in sequential IDs)
        if row_id != expected_id:
            return {
                "ok": False,
                "checked": checked,
                "first_broken_id": expected_id,
                "reason": f"deleted row detected: expected id {expected_id}, found id {row_id}",
                "head_hash": expected_prev,
                "anchor": read_anchor(anchor_dir),
            }

        # Check prev_hash link
        if stored_prev != expected_prev:
            return {
                "ok": False,
                "checked": checked,
                "first_broken_id": row_id,
                "reason": f"prev_hash mismatch at id {row_id} (possible deletion or reordering)",
                "head_hash": expected_prev,
                "anchor": read_anchor(anchor_dir),
            }

        # Recompute row hash
        recomputed = compute_event_hash(expected_prev, ts, host, raw_line)
        if stored_hash != recomputed:
            return {
                "ok": False,
                "checked": checked,
                "first_broken_id": row_id,
                "reason": f"hash mismatch at id {row_id} (modified log record)",
                "head_hash": recomputed,
                "anchor": read_anchor(anchor_dir),
            }

        checked += 1
        expected_prev = recomputed
        expected_id += 1

    # Compare recomputed head and count against anchor
    anchor = read_anchor(anchor_dir)
    if anchor is not None:
        anchor_head = anchor.get("head_hash")
        anchor_count = anchor.get("row_count")
        if expected_prev != anchor_head or checked != anchor_count:
            broken_id = (checked + 1) if checked < (anchor_count or 0) else (checked if checked > 0 else None)
            return {
                "ok": False,
                "checked": checked,
                "first_broken_id": broken_id,
                "reason": "chain head does not match anchor (possible truncation or full rewrite)",
                "head_hash": expected_prev,
                "anchor": anchor,
            }

    return {
        "ok": True,
        "checked": checked,
        "first_broken_id": None,
        "reason": "chain intact",
        "head_hash": expected_prev,
        "anchor": anchor,
    }
