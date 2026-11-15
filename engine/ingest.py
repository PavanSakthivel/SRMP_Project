"""Log ingestion: parse log file, insert events with SHA-256 chaining, and write anchor."""

from pathlib import Path
import sqlite3
from typing import Any

from engine.chain import GENESIS_HASH, compute_event_hash, write_anchor
from engine.parse import parse_file


def ingest_logs(
    conn: sqlite3.Connection,
    log_path: Path | str,
    anchor_dir: Path | None = None,
) -> dict[str, Any]:
    """Parse log lines from log_path, store in log_events with hash chain, and anchor head."""
    events = parse_file(log_path)
    conn.execute("DELETE FROM log_events")

    prev_hash = GENESIS_HASH
    count = 0

    for idx, ev in enumerate(events, start=1):
        curr_hash = compute_event_hash(prev_hash, ev["ts"], ev["host"], ev["raw_line"])
        conn.execute(
            """
            INSERT INTO log_events(
                id, ts, host, program, raw_line, src_ip, dst_port, username, event_type, prev_hash, hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                idx,
                ev["ts"],
                ev["host"],
                ev["program"],
                ev["raw_line"],
                ev["src_ip"],
                ev["dst_port"],
                ev["username"],
                ev["event_type"],
                prev_hash,
                curr_hash,
            ),
        )
        prev_hash = curr_hash
        count += 1

    conn.commit()
    anchor_info = write_anchor(prev_hash, count, anchor_dir=anchor_dir)
    return {
        "ingested_count": count,
        "head_hash": prev_hash,
        "anchor": anchor_info,
    }
