"""Tests for engine/chain.py: clean verification, modified row, deleted row, and anchor mismatch."""

import json
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from engine.chain import verify_chain
from engine.db import DATA_DIR, get_connection, init_db
from engine.ingest import ingest_logs
from scripts.tamper_demo import tamper_record


def test_clean_chain_verifies_and_editing_row_caught(tmp_path: Path):
    db_path = tmp_path / "test.db"
    anchor_dir = tmp_path / "anchor"
    conn = get_connection(db_path)
    init_db(conn, reset=True)
    ingest_logs(conn, DATA_DIR / "sample" / "auth.log", anchor_dir=anchor_dir)

    res_clean = verify_chain(conn, anchor_dir=anchor_dir)
    assert res_clean["ok"] is True
    assert res_clean["first_broken_id"] is None
    assert res_clean["checked"] == 157
    conn.close()

    # Tamper with record 150 via tamper_record
    tamper_record(db_path=db_path, record_id=150)

    conn = get_connection(db_path)
    res_tampered = verify_chain(conn, anchor_dir=anchor_dir)
    conn.close()
    assert res_tampered["ok"] is False
    assert res_tampered["first_broken_id"] == 150


def test_deleted_row_is_caught(tmp_path: Path):
    db_path = tmp_path / "test_del.db"
    anchor_dir = tmp_path / "anchor_del"
    conn = get_connection(db_path)
    init_db(conn, reset=True)
    ingest_logs(conn, DATA_DIR / "sample" / "auth.log", anchor_dir=anchor_dir)

    conn.execute("DELETE FROM log_events WHERE id = 25")
    conn.commit()

    res = verify_chain(conn, anchor_dir=anchor_dir)
    conn.close()
    assert res["ok"] is False
    assert res["first_broken_id"] == 25


def test_anchor_mismatch_is_caught(tmp_path: Path):
    db_path = tmp_path / "test_anchor.db"
    anchor_dir = tmp_path / "anchor_mismatch"
    conn = get_connection(db_path)
    init_db(conn, reset=True)
    ingest_logs(conn, DATA_DIR / "sample" / "auth.log", anchor_dir=anchor_dir)

    # Corrupt anchor head hash to simulate truncation / rewrite mismatch
    head_file = anchor_dir / "head.txt"
    anchor_data = json.loads(head_file.read_text(encoding="utf-8"))
    anchor_data["head_hash"] = "f" * 64
    head_file.write_text(json.dumps(anchor_data), encoding="utf-8")

    res = verify_chain(conn, anchor_dir=anchor_dir)
    conn.close()
    assert res["ok"] is False
    assert res["reason"] == "chain head does not match anchor (possible truncation or full rewrite)"
