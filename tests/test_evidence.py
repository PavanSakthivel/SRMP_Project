"""Tests for engine/evidence.py verifying 6 issues on main log, 0 on lockout log, and direct evidence counts."""

from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from engine.db import DATA_DIR
from scripts.run_pipeline import run_pipeline


def test_six_issues_for_main_log_and_direct_evidence_count(tmp_path: Path):
    db_path = tmp_path / "main.db"
    anchor_dir = tmp_path / "anchor_main"
    res = run_pipeline(
        log_path=DATA_DIR / "sample" / "auth.log",
        db_path=db_path,
        anchor_dir=anchor_dir,
        verbose=False,
    )

    assert len(res["issues"]) == 6
    for issue in res["issues"]:
        assert issue["status"] == "Open"

    # Total triggering log lines across S1..S6: 1 + 1 + 40 + 12 + 15 + 15 = 84
    total_triggering_lines = sum(len(d["evidence_event_ids"]) for d in res["detections"])
    assert total_triggering_lines == 84

    direct_evidence = [e for e in res["evidence"] if e["type"] == "direct"]
    indirect_evidence = [e for e in res["evidence"] if e["type"] == "indirect"]
    assert len(direct_evidence) == total_triggering_lines
    assert len(indirect_evidence) == 12  # 2 per detection (correlation + risk score)


def test_zero_issues_for_lockout_log(tmp_path: Path):
    db_path = tmp_path / "lockout.db"
    anchor_dir = tmp_path / "anchor_lockout"
    res = run_pipeline(
        log_path=DATA_DIR / "sample" / "auth_with_lockout.log",
        db_path=db_path,
        anchor_dir=anchor_dir,
        verbose=False,
    )

    # Brute-force detection is present (12 failed logins), but AC-7 passes because lockout line follows
    assert len(res["detections"]) == 1
    assert res["detections"][0]["threat_id"] == "T1110"
    assert len(res["issues"]) == 0
