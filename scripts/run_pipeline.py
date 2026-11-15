"""Run the complete RiskSIEM pipeline end-to-end (ingest -> detect -> score -> evidence -> issues)."""

import argparse
from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from engine.chain import verify_chain
from engine.db import ANCHOR_DIR, DATA_DIR, DEFAULT_DB_PATH, get_connection, init_db
from engine.detect import run_detections_on_db
from engine.evidence import generate_evidence_and_issues
from engine.ingest import ingest_logs
from engine.risk import score_detections_in_db
from scripts.generate_logs import main as generate_logs_main


def run_pipeline(
    log_path: Path | str | None = None,
    db_path: Path | str | None = None,
    anchor_dir: Path | None = None,
    data_dir: Path | None = None,
    verbose: bool = True,
) -> dict:
    """Execute the full RiskSIEM pipeline idempotently."""
    target_log = Path(log_path) if log_path is not None else (DATA_DIR / "sample" / "auth.log")
    if not target_log.exists():
        generate_logs_main()

    conn = get_connection(db_path)
    try:
        init_db(conn, reset=True, data_dir=data_dir)
        ingest_res = ingest_logs(conn, target_log, anchor_dir=anchor_dir)
        detections = run_detections_on_db(conn, data_dir=data_dir)
        scored = score_detections_in_db(conn, detections, data_dir=data_dir)
        ev_issues = generate_evidence_and_issues(conn, scored, data_dir=data_dir)
        chain_status = verify_chain(conn, anchor_dir=anchor_dir)
    finally:
        conn.close()

    if verbose:
        print("=" * 88)
        print("RiskSIEM Pipeline Execution Summary")
        print("=" * 88)
        print(f"Log file ingested : {target_log} ({ingest_res['ingested_count']} events)")
        print(f"Chain head SHA256 : {ingest_res['head_hash']}")
        print(f"Chain verify      : {'OK' if chain_status['ok'] else 'BROKEN'} ({chain_status['reason']})")
        print("-" * 88)
        print(
            f"{'Scen':<5} {'Asset':<14} {'Threat':<7} {'n':>4} {'Sev':>4} "
            f"{'L':>3} {'I':>3} {'Risk':>5} {'Band':<9} {'BaseRk':>6} {'RiskRk':>6} {'Shift':>6}"
        )
        print("-" * 88)
        for s in sorted(scored, key=lambda x: x["detection_id"]):
            shift_str = f"+{s['shift']}" if s["shift"] > 0 else str(s["shift"])
            asset_label = f"{s['asset_id']} {s['host']}"
            print(
                f"S{s['detection_id']:<4} {asset_label:<14} {s['threat_id']:<7} {s['event_count']:>4} "
                f"{s['severity']:>4} {s['likelihood']:>3} {s['impact']:>3} {s['risk']:>5} "
                f"{s['band']:<9} {s['baseline_rank']:>6} {s['risk_rank']:>6} {shift_str:>6}"
            )
        print("-" * 88)
        print(
            f"Evidence items    : {len(ev_issues['evidence'])} "
            f"({sum(1 for e in ev_issues['evidence'] if e['type'] == 'direct')} direct, "
            f"{sum(1 for e in ev_issues['evidence'] if e['type'] == 'indirect')} indirect)"
        )
        print(f"Open issues       : {len(ev_issues['issues'])}")
        print("=" * 88)

    return {
        "ingest": ingest_res,
        "detections": detections,
        "scored": scored,
        "evidence": ev_issues["evidence"],
        "issues": ev_issues["issues"],
        "control_results": ev_issues["control_results"],
        "chain": chain_status,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run RiskSIEM pipeline end-to-end.")
    parser.add_argument(
        "--log-file",
        type=str,
        default=str(DATA_DIR / "sample" / "auth.log"),
        help="Path to input syslog file (default: data/sample/auth.log)",
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=str(DEFAULT_DB_PATH),
        help="Path to SQLite database (default: riskSIEM.db)",
    )
    parser.add_argument(
        "--anchor-dir",
        type=str,
        default=str(ANCHOR_DIR),
        help="Path to anchor directory (default: anchor/)",
    )
    args = parser.parse_args()
    run_pipeline(
        log_path=Path(args.log_file),
        db_path=Path(args.db_path),
        anchor_dir=Path(args.anchor_dir),
        verbose=True,
    )


if __name__ == "__main__":
    main()
