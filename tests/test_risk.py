"""Tests for engine/risk.py verifying Section 11 golden table and round_half_up edge cases."""

from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from engine.db import DATA_DIR, get_connection
from engine.detect import detect_events
from engine.parse import parse_file
from engine.risk import (
    add_risk_to_db,
    delete_risk_from_db,
    round_half_up,
    score_and_rank_detections,
    update_risk_in_db,
)
from scripts.run_pipeline import run_pipeline


def test_round_half_up_edge_cases():
    assert round_half_up(1.0) == 1
    assert round_half_up(1.4) == 1
    assert round_half_up(1.5) == 2
    assert round_half_up(2.5) == 3
    assert round_half_up(3.5) == 4
    assert round_half_up(4.5) == 5
    assert round_half_up(2.4999) == 2


def test_section_11_golden_table_exact_match():
    events = parse_file(DATA_DIR / "sample" / "auth.log")
    detections = detect_events(events)
    scored = score_and_rank_detections(detections)

    # Golden fixture table from Section 11:
    # (det_id, asset_id, host, threat_id, n, severity, L, I, Risk, Band, baseline_rank, risk_rank, shift)
    golden = [
        (1, "A4", "ws-lab-01", "T1548", 1, 5, 4, 3, 12, "High", 1, 4, -3),
        (2, "A1", "db-srv-01", "T1548", 1, 5, 4, 5, 20, "Critical", 2, 1, 1),
        (3, "A6", "gw-01", "T1110", 40, 4, 5, 2, 10, "Medium", 3, 5, -2),
        (4, "A2", "pay-srv-01", "T1110", 12, 4, 4, 5, 20, "Critical", 4, 2, 2),
        (5, "A6", "gw-01", "T1046", 15, 3, 4, 2, 8, "Medium", 5, 6, -1),
        (6, "A5", "exam-srv-01", "T1046", 15, 3, 3, 4, 12, "High", 6, 3, 3),
    ]

    scored_by_id = {s["detection_id"]: s for s in scored}
    assert len(scored_by_id) == 6

    for (
        det_id,
        asset_id,
        host,
        threat_id,
        n,
        sev,
        l_val,
        i_val,
        risk_val,
        band,
        base_rk,
        risk_rk,
        shift,
    ) in golden:
        row = scored_by_id[det_id]
        assert row["asset_id"] == asset_id
        assert row["host"] == host
        assert row["threat_id"] == threat_id
        assert row["event_count"] == n
        assert row["severity"] == sev
        assert row["likelihood"] == l_val
        assert row["impact"] == i_val
        assert row["risk"] == risk_val
        assert row["band"] == band
        assert row["baseline_rank"] == base_rk
        assert row["risk_rank"] == risk_rk
        assert row["shift"] == shift


def test_interactive_risk_crud_add_modify_delete(tmp_path: Path):
    db_path = tmp_path / "crud.db"
    anchor_dir = tmp_path / "anchor_crud"
    run_pipeline(
        log_path=DATA_DIR / "sample" / "auth.log",
        db_path=db_path,
        anchor_dir=anchor_dir,
        verbose=False,
    )

    conn = get_connection(db_path)
    try:
        # 1. Add a new risk with L=5, I=5 -> Risk=25 (Critical), should become Risk Rank #1
        new_id = add_risk_to_db(
            conn,
            title="Phished administrator credentials",
            asset_id="A1",
            threat_id="T1110",
            likelihood=5,
            impact=5,
            event_count=25,
            severity=5,
            status="In treatment",
            owner="IT Security",
        )
        assert new_id == 7

        row7 = conn.execute("SELECT * FROM risk_scores WHERE detection_id = ?", (new_id,)).fetchone()
        assert row7["risk"] == 25
        assert row7["band"] == "Critical"
        assert row7["risk_rank"] == 1

        # 2. Modify risk 7 to L=2, I=2 -> Risk=4 (Low), status='Verified'
        update_risk_in_db(
            conn,
            detection_id=new_id,
            likelihood=2,
            impact=2,
            status="Verified",
            title="Updated Phished Admin Scenario",
        )
        row7_mod = conn.execute("SELECT * FROM risk_scores WHERE detection_id = ?", (new_id,)).fetchone()
        assert row7_mod["risk"] == 4
        assert row7_mod["band"] == "Low"
        assert row7_mod["risk_rank"] == 7

        iss7 = conn.execute("SELECT * FROM issues WHERE detection_id = ?", (new_id,)).fetchone()
        assert iss7["status"] == "Verified"
        assert iss7["risk_score"] == 4

        # 3. Delete risk 7 -> back to 6 detections with ranks 1..6
        delete_risk_from_db(conn, detection_id=new_id)
        cnt = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        assert cnt == 6
        ranks = [
            r[0]
            for r in conn.execute("SELECT risk_rank FROM risk_scores ORDER BY risk_rank ASC").fetchall()
        ]
        assert ranks == [1, 2, 3, 4, 5, 6]
    finally:
        conn.close()

