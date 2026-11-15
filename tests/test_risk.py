"""Tests for engine/risk.py verifying Section 11 golden table and round_half_up edge cases."""

from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from engine.db import DATA_DIR
from engine.detect import detect_events
from engine.parse import parse_file
from engine.risk import round_half_up, score_and_rank_detections


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
