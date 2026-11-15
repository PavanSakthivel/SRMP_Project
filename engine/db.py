"""Database connection, schema management, and CSV reference data loaders."""

import csv
import sqlite3
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / "data"
ANCHOR_DIR = ROOT_DIR / "anchor"
DEFAULT_DB_PATH = ROOT_DIR / "riskSIEM.db"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS assets(
    asset_id TEXT PRIMARY KEY,
    hostname TEXT,
    name TEXT,
    type TEXT,
    owner TEXT,
    value INT,
    c INT,
    i INT,
    a INT
);

CREATE TABLE IF NOT EXISTS log_events(
    id INTEGER PRIMARY KEY,
    ts TEXT,
    host TEXT,
    program TEXT,
    raw_line TEXT,
    src_ip TEXT,
    dst_port INT,
    username TEXT,
    event_type TEXT,
    prev_hash TEXT,
    hash TEXT
);

CREATE TABLE IF NOT EXISTS detections(
    detection_id INTEGER PRIMARY KEY,
    threat_id TEXT,
    host TEXT,
    asset_id TEXT,
    source TEXT,
    event_count INT,
    first_seen TEXT,
    last_seen TEXT,
    details TEXT
);

CREATE TABLE IF NOT EXISTS risk_scores(
    detection_id INT PRIMARY KEY,
    impact INT,
    likelihood INT,
    freq_bonus REAL,
    risk INT,
    band TEXT,
    severity INT,
    baseline_rank INT,
    risk_rank INT
);

CREATE TABLE IF NOT EXISTS evidence(
    evidence_id INTEGER PRIMARY KEY,
    detection_id INT,
    type TEXT,
    source_host TEXT,
    ts TEXT,
    description TEXT,
    log_event_id INT,
    control_nist TEXT,
    control_cis TEXT
);

CREATE TABLE IF NOT EXISTS issues(
    issue_id INTEGER PRIMARY KEY,
    detection_id INT,
    title TEXT,
    asset_id TEXT,
    owner TEXT,
    control_nist TEXT,
    control_cis TEXT,
    risk_score INT,
    risk_band TEXT,
    evidence_ids TEXT,
    recommended_treatment TEXT,
    status TEXT,
    created_at TEXT
);
"""

DROP_TABLES_SQL = """
DROP TABLE IF EXISTS issues;
DROP TABLE IF EXISTS evidence;
DROP TABLE IF EXISTS risk_scores;
DROP TABLE IF EXISTS detections;
DROP TABLE IF EXISTS log_events;
DROP TABLE IF EXISTS assets;
"""


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Return a SQLite connection with sqlite3.Row factory."""
    target = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    conn = sqlite3.connect(str(target))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn: sqlite3.Connection, reset: bool = False, data_dir: Path | None = None) -> None:
    """Create schema (optionally resetting tables) and populate the assets table from CSV."""
    if reset:
        conn.executescript(DROP_TABLES_SQL)
    conn.executescript(SCHEMA_SQL)
    load_assets_into_db(conn, data_dir=data_dir)
    conn.commit()


def _read_csv(filename: str, data_dir: Path | None = None) -> list[dict[str, str]]:
    base = data_dir if data_dir is not None else DATA_DIR
    path = base / filename
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return [dict(row) for row in reader]


def load_assets_csv(data_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    """Return dict keyed by asset_id with typed fields, plus hostname lookup support."""
    rows = _read_csv("assets.csv", data_dir)
    assets: dict[str, dict[str, Any]] = {}
    for r in rows:
        assets[r["asset_id"]] = {
            "asset_id": r["asset_id"],
            "hostname": r["hostname"],
            "name": r["name"],
            "type": r["type"],
            "owner": r["owner"],
            "value": int(r["value"]),
            "C": int(r["C"]),
            "I": int(r["I"]),
            "A": int(r["A"]),
            "c": int(r["C"]),
            "i": int(r["I"]),
            "a": int(r["A"]),
        }
    return assets


def load_assets_by_hostname(data_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    """Return dict keyed by hostname."""
    assets = load_assets_csv(data_dir)
    return {a["hostname"]: a for a in assets.values()}


def load_assets_into_db(conn: sqlite3.Connection, data_dir: Path | None = None) -> None:
    """Load assets.csv into the SQLite assets table."""
    assets = load_assets_csv(data_dir)
    conn.execute("DELETE FROM assets")
    for a in assets.values():
        conn.execute(
            """
            INSERT INTO assets(asset_id, hostname, name, type, owner, value, c, i, a)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                a["asset_id"],
                a["hostname"],
                a["name"],
                a["type"],
                a["owner"],
                a["value"],
                a["C"],
                a["I"],
                a["A"],
            ),
        )


def load_threats_csv(data_dir: Path | None = None) -> dict[str, dict[str, Any]]:
    """Return dict keyed by threat_id."""
    rows = _read_csv("threats.csv", data_dir)
    threats: dict[str, dict[str, Any]] = {}
    for r in rows:
        threats[r["threat_id"]] = {
            "threat_id": r["threat_id"],
            "name": r["name"],
            "mitre_id": r["mitre_id"],
            "base_likelihood": int(r["base_likelihood"]),
            "primary_dimension": r["primary_dimension"].strip().upper(),
            "default_severity": int(r["default_severity"]),
        }
    return threats


def load_vulnerabilities_csv(data_dir: Path | None = None) -> dict[str, dict[str, str]]:
    """Return dict keyed by vuln_id."""
    rows = _read_csv("vulnerabilities.csv", data_dir)
    return {r["vuln_id"]: r for r in rows}


def load_tv_pairs_csv(data_dir: Path | None = None) -> list[dict[str, str]]:
    """Return list of {threat_id, vuln_id} pairs."""
    return _read_csv("tv_pairs.csv", data_dir)


def load_exposure_csv(data_dir: Path | None = None) -> dict[str, dict[str, int]]:
    """Return nested dict exposure[asset_id][threat_id] = int (1-5)."""
    rows = _read_csv("exposure.csv", data_dir)
    exposure: dict[str, dict[str, int]] = {}
    for r in rows:
        asset_id = r["asset_id"]
        exposure[asset_id] = {
            k: int(v) for k, v in r.items() if k != "asset_id"
        }
    return exposure


def load_control_map_csv(data_dir: Path | None = None) -> dict[str, dict[str, str]]:
    """Return dict keyed by threat_id with nist_800_53, cis_v8, control_name, evidence_test."""
    rows = _read_csv("control_map.csv", data_dir)
    return {r["threat_id"]: r for r in rows}


def load_treatments_csv(data_dir: Path | None = None) -> dict[str, str]:
    """Return dict mapping threat_id -> recommended treatment string."""
    rows = _read_csv("treatments.csv", data_dir)
    return {r["threat_id"]: r["treatment"] for r in rows}
