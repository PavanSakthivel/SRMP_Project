"""Reset demo: delete the database and anchor files and re-run full ingestion & pipeline."""

import argparse
from pathlib import Path
import shutil
import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from engine.db import ANCHOR_DIR, DATA_DIR, DEFAULT_DB_PATH
from scripts.run_pipeline import run_pipeline


def reset_environment(
    db_path: Path | str | None = None,
    anchor_dir: Path | str | None = None,
    log_path: Path | str | None = None,
    verbose: bool = True,
) -> dict:
    """Delete SQLite database and anchor directory, then re-run the full pipeline."""
    target_db = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    target_anchor = Path(anchor_dir) if anchor_dir is not None else ANCHOR_DIR
    target_log = Path(log_path) if log_path is not None else (DATA_DIR / "sample" / "auth.log")

    if target_db.exists():
        target_db.unlink()

    if target_anchor.exists():
        shutil.rmtree(target_anchor)

    if verbose:
        print(f"[RESET DEMO] Removed {target_db.name} and {target_anchor.name}/, re-running pipeline...")

    return run_pipeline(
        log_path=target_log,
        db_path=target_db,
        anchor_dir=target_anchor,
        verbose=verbose,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset database and anchor and re-run pipeline.")
    parser.add_argument("--db-path", type=str, default=str(DEFAULT_DB_PATH), help="Database path")
    parser.add_argument("--anchor-dir", type=str, default=str(ANCHOR_DIR), help="Anchor directory")
    parser.add_argument(
        "--log-file",
        type=str,
        default=str(DATA_DIR / "sample" / "auth.log"),
        help="Log file to ingest",
    )
    args = parser.parse_args()
    reset_environment(
        db_path=args.db_path,
        anchor_dir=args.anchor_dir,
        log_path=args.log_file,
        verbose=True,
    )


if __name__ == "__main__":
    main()
