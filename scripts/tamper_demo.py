"""Tamper demo: directly edit one raw_line in SQLite (default id=150) without recomputing hashes."""

import argparse
from pathlib import Path
import re
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from engine.db import DEFAULT_DB_PATH, get_connection

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def tamper_record(db_path: Path | str | None = None, record_id: int = 150) -> dict:
    """Modify raw_line on record_id by replacing a source IP without updating hash chain."""
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            "SELECT id, raw_line, src_ip FROM log_events WHERE id = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"Record id={record_id} not found in log_events.")

        old_line = row["raw_line"]
        if IP_RE.search(old_line):
            new_line = IP_RE.sub("192.0.2.254", old_line, count=1)
            if new_line == old_line:
                new_line = IP_RE.sub("192.0.2.253", old_line, count=1)
        else:
            new_line = old_line + " [SRC=192.0.2.254]"

        conn.execute(
            "UPDATE log_events SET raw_line = ? WHERE id = ?",
            (new_line, record_id),
        )
        conn.commit()
        return {
            "id": record_id,
            "old_line": old_line,
            "new_line": new_line,
        }
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Tamper with a stored log line in riskSIEM.db.")
    parser.add_argument("--id", type=int, default=150, help="Record ID to tamper (default: 150)")
    parser.add_argument("--db-path", type=str, default=str(DEFAULT_DB_PATH), help="Database path")
    args = parser.parse_args()

    res = tamper_record(db_path=args.db_path, record_id=args.id)
    print(f"[TAMPER DEMO] Modified log_events id={res['id']} without recomputing hashes:")
    print(f"  BEFORE: {res['old_line']}")
    print(f"  AFTER : {res['new_line']}")


if __name__ == "__main__":
    main()
