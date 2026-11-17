"""Risk scoring formulas, risk banding, baseline vs. risk ranking, and residual risk calculation."""

from datetime import datetime
import json
import math
from pathlib import Path
import sqlite3
from typing import Any

from engine.db import (
    load_assets_csv,
    load_control_map_csv,
    load_exposure_csv,
    load_threats_csv,
    load_treatments_csv,
    load_tv_pairs_csv,
    load_vulnerabilities_csv,
)


def round_half_up(x: float) -> int:
    """Round half up as specified: floor(x + 0.5)."""
    return int(math.floor(x + 0.5))


def clamp(val: int, low: int = 1, high: int = 5) -> int:
    """Clamp integer val to [low, high]."""
    return max(low, min(high, val))


def compute_frequency_bonus(threat_id: str, event_count: int) -> float:
    """Return frequency bonus F based on threat_id and event_count n."""
    if threat_id == "T1110":
        if event_count < 20:
            return 0.0
        if event_count <= 39:
            return 0.5
        return 1.0
    if threat_id == "T1046":
        if event_count < 25:
            return 0.0
        if event_count <= 49:
            return 0.5
        return 1.0
    if threat_id == "T1548":
        return 0.0
    return 0.0


def get_risk_band(risk_score: int) -> str:
    """Map risk score (1-25) to band: Critical (20-25), High (12-19), Medium (6-11), Low (1-5)."""
    if risk_score >= 20:
        return "Critical"
    if risk_score >= 12:
        return "High"
    if risk_score >= 6:
        return "Medium"
    return "Low"


def score_single_detection(
    detection: dict[str, Any],
    asset: dict[str, Any],
    threat: dict[str, Any],
    exposure_val: int,
) -> dict[str, Any]:
    """Compute Impact (I), Frequency Bonus (F), Likelihood (L), Risk (R), and Band for one detection."""
    dim = threat["primary_dimension"].upper()  # 'C', 'I', or 'A'
    dim_rating = int(asset[dim])
    asset_val = int(asset["value"])

    impact = clamp(round_half_up((asset_val + dim_rating) / 2.0), 1, 5)
    freq_bonus = compute_frequency_bonus(threat["threat_id"], int(detection["event_count"]))
    base_l = int(threat["base_likelihood"])
    likelihood = clamp(round_half_up((base_l + int(exposure_val)) / 2.0 + freq_bonus), 1, 5)
    risk = likelihood * impact
    band = get_risk_band(risk)

    return {
        "detection_id": int(detection["detection_id"]),
        "impact": impact,
        "likelihood": likelihood,
        "freq_bonus": freq_bonus,
        "risk": risk,
        "band": band,
        "severity": int(threat["default_severity"]),
    }


def compute_residual_score(
    detection: dict[str, Any],
    asset: dict[str, Any],
    threat: dict[str, Any],
    original_exposure: int,
) -> dict[str, Any]:
    """Compute residual risk after applying treatment (reduces exposure by 2, minimum 1)."""
    reduced_exposure = max(1, int(original_exposure) - 2)
    scored = score_single_detection(detection, asset, threat, reduced_exposure)
    scored["reduced_exposure"] = reduced_exposure
    scored["original_exposure"] = int(original_exposure)
    return scored


def score_and_rank_detections(
    detections: list[dict[str, Any]],
    assets: dict[str, dict[str, Any]] | None = None,
    threats: dict[str, dict[str, Any]] | None = None,
    exposure: dict[str, dict[str, int]] | None = None,
    data_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Score all detections and compute baseline_rank, risk_rank, and shift."""
    assets_map = assets if assets is not None else load_assets_csv(data_dir)
    threats_map = threats if threats is not None else load_threats_csv(data_dir)
    exposure_map = exposure if exposure is not None else load_exposure_csv(data_dir)

    host_to_asset = {a["hostname"]: a for a in assets_map.values()}

    enriched: list[dict[str, Any]] = []
    for det in detections:
        asset_id = det.get("asset_id")
        if asset_id and asset_id in assets_map:
            asset = assets_map[asset_id]
        else:
            asset = host_to_asset[det["host"]]
            asset_id = asset["asset_id"]

        threat_id = det["threat_id"]
        threat = threats_map[threat_id]
        exp_val = exposure_map[asset_id][threat_id]

        scored = score_single_detection(det, asset, threat, exp_val)
        merged = {
            **det,
            "asset_id": asset_id,
            "asset_name": asset["name"],
            "threat_name": threat["name"],
            "exposure": exp_val,
            **scored,
        }
        enriched.append(merged)

    # Baseline ranking: default_severity DESC, event_count DESC, first_seen ASC
    baseline_sorted = sorted(
        enriched,
        key=lambda d: (
            -int(d["severity"]),
            -int(d["event_count"]),
            datetime.fromisoformat(d["first_seen"]),
            int(d["detection_id"]),
        ),
    )
    baseline_ranks = {
        d["detection_id"]: rank for rank, d in enumerate(baseline_sorted, start=1)
    }

    # Risk ranking: R DESC, I DESC, default_severity DESC, first_seen ASC
    risk_sorted = sorted(
        enriched,
        key=lambda d: (
            -int(d["risk"]),
            -int(d["impact"]),
            -int(d["severity"]),
            datetime.fromisoformat(d["first_seen"]),
            int(d["detection_id"]),
        ),
    )
    risk_ranks = {
        d["detection_id"]: rank for rank, d in enumerate(risk_sorted, start=1)
    }

    for d in enriched:
        det_id = d["detection_id"]
        b_rank = baseline_ranks[det_id]
        r_rank = risk_ranks[det_id]
        d["baseline_rank"] = b_rank
        d["risk_rank"] = r_rank
        d["shift"] = b_rank - r_rank

    return enriched


def score_detections_in_db(
    conn: sqlite3.Connection,
    detections: list[dict[str, Any]],
    data_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Compute risk scores and rankings for detections and persist them in risk_scores table."""
    scored_list = score_and_rank_detections(detections, data_dir=data_dir)
    conn.execute("DELETE FROM risk_scores")

    for s in scored_list:
        conn.execute(
            """
            INSERT INTO risk_scores(
                detection_id, impact, likelihood, freq_bonus, risk, band, severity, baseline_rank, risk_rank
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                s["detection_id"],
                s["impact"],
                s["likelihood"],
                s["freq_bonus"],
                s["risk"],
                s["band"],
                s["severity"],
                s["baseline_rank"],
                s["risk_rank"],
            ),
        )
    conn.commit()
    return scored_list


def parse_detection_details(raw_details: str | None) -> dict[str, Any]:
    """Parse detections.details JSON or plain string into a normalized dictionary."""
    if not raw_details:
        return {"summary": "", "evidence_event_ids": []}
    try:
        parsed = json.loads(raw_details)
        if isinstance(parsed, dict):
            parsed.setdefault("summary", "")
            parsed.setdefault("evidence_event_ids", [])
            return parsed
    except Exception:
        pass
    return {"summary": str(raw_details), "evidence_event_ids": []}


def get_default_vuln_for_threat(threat_id: str, data_dir: Path | None = None) -> str:
    """Return a formatted vulnerability description for a threat_id from tv_pairs.csv & vulnerabilities.csv."""
    try:
        tv_pairs = load_tv_pairs_csv(data_dir)
        vulns = load_vulnerabilities_csv(data_dir)
        matched = [
            f"{vulns[p['vuln_id']]['name']}"
            for p in tv_pairs
            if p["threat_id"] == threat_id and p["vuln_id"] in vulns
        ]
        if matched:
            return " + ".join(matched)
    except Exception:
        pass
    return "Unmitigated security control weakness"


def get_default_scenario_title(threat_id: str, asset_name: str, source: str = "") -> str:
    """Return a concise, human-readable scenario title for a detection."""
    if threat_id == "T1110":
        return f"Brute-force password attack on {asset_name}"
    if threat_id == "T1046":
        return f"Network port scan & reconnaissance on {asset_name}"
    if threat_id == "T1548":
        acct = f" by '{source}'" if source else ""
        return f"Unauthorised root privilege escalation on {asset_name}{acct}"
    return f"Security risk scenario on {asset_name} ({threat_id})"


def _safe_parse_iso(ts_str: str | None) -> datetime:
    if not ts_str:
        return datetime(2026, 11, 10, 12, 0, 0)
    try:
        return datetime.fromisoformat(ts_str)
    except Exception:
        return datetime(2026, 11, 10, 12, 0, 0)


def recalculate_ranks_in_db(conn: sqlite3.Connection) -> None:
    """Recompute risk=L*I, band, baseline_rank, and risk_rank for all rows in risk_scores and sync issues/evidence."""
    rows = conn.execute(
        """
        SELECT d.detection_id, d.threat_id, d.host, d.asset_id, d.source, d.event_count,
               d.first_seen, d.last_seen, d.details,
               r.impact, r.likelihood, r.freq_bonus, r.severity
        FROM detections d
        JOIN risk_scores r ON d.detection_id = r.detection_id
        """
    ).fetchall()

    if not rows:
        conn.commit()
        return

    items: list[dict[str, Any]] = []
    for r in rows:
        l_val = clamp(int(r["likelihood"]), 1, 5)
        i_val = clamp(int(r["impact"]), 1, 5)
        risk_val = l_val * i_val
        band_val = get_risk_band(risk_val)
        items.append(
            {
                "detection_id": int(r["detection_id"]),
                "threat_id": r["threat_id"],
                "host": r["host"],
                "asset_id": r["asset_id"],
                "source": r["source"],
                "event_count": int(r["event_count"] or 1),
                "first_seen": r["first_seen"] or "2026-11-10T10:00:00+05:30",
                "last_seen": r["last_seen"] or "2026-11-10T10:00:00+05:30",
                "details": r["details"],
                "impact": i_val,
                "likelihood": l_val,
                "freq_bonus": float(r["freq_bonus"] or 0.0),
                "risk": risk_val,
                "band": band_val,
                "severity": int(r["severity"] or 3),
            }
        )

    baseline_sorted = sorted(
        items,
        key=lambda d: (
            -int(d["severity"]),
            -int(d["event_count"]),
            _safe_parse_iso(d["first_seen"]),
            int(d["detection_id"]),
        ),
    )
    baseline_ranks = {d["detection_id"]: idx for idx, d in enumerate(baseline_sorted, start=1)}

    risk_sorted = sorted(
        items,
        key=lambda d: (
            -int(d["risk"]),
            -int(d["impact"]),
            -int(d["severity"]),
            _safe_parse_iso(d["first_seen"]),
            int(d["detection_id"]),
        ),
    )
    risk_ranks = {d["detection_id"]: idx for idx, d in enumerate(risk_sorted, start=1)}

    for item in items:
        det_id = item["detection_id"]
        b_rk = baseline_ranks[det_id]
        r_rk = risk_ranks[det_id]
        conn.execute(
            """
            UPDATE risk_scores
            SET impact = ?, likelihood = ?, risk = ?, band = ?, severity = ?,
                baseline_rank = ?, risk_rank = ?
            WHERE detection_id = ?
            """,
            (
                item["impact"],
                item["likelihood"],
                item["risk"],
                item["band"],
                item["severity"],
                b_rk,
                r_rk,
                det_id,
            ),
        )

        # Sync corresponding issue risk_score and risk_band if present
        conn.execute(
            """
            UPDATE issues
            SET risk_score = ?, risk_band = ?, asset_id = ?
            WHERE detection_id = ?
            """,
            (item["risk"], item["band"], item["asset_id"], det_id),
        )

        # Sync indirect risk score evidence description
        risk_desc = (
            f"Computed risk score record: Risk={item['risk']} ({item['band']}) "
            f"[Likelihood L={item['likelihood']} (freq_bonus={item['freq_bonus']}), "
            f"Impact I={item['impact']}, Baseline Rank={b_rk}, Risk Rank={r_rk}]"
        )
        conn.execute(
            """
            UPDATE evidence
            SET description = ?, source_host = ?
            WHERE detection_id = ? AND type = 'indirect' AND description LIKE 'Computed risk score record:%'
            """,
            (risk_desc, item["host"], det_id),
        )

    conn.commit()


def add_risk_to_db(
    conn: sqlite3.Connection,
    title: str,
    asset_id: str,
    threat_id: str,
    likelihood: int,
    impact: int,
    event_count: int = 1,
    severity: int | None = None,
    source: str = "manual-entry",
    status: str = "Open",
    vuln_desc: str = "",
    owner: str | None = None,
    recommended_treatment: str | None = None,
    summary: str | None = None,
    data_dir: Path | None = None,
) -> int:
    """Insert a new risk scenario into detections, risk_scores, evidence, and issues, and recompute ranks."""
    assets_db_rows = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchall()
    if assets_db_rows:
        asset_row = dict(assets_db_rows[0])
    else:
        assets_csv = load_assets_csv(data_dir)
        asset_row = assets_csv.get(
            asset_id,
            {
                "asset_id": asset_id,
                "hostname": f"{asset_id.lower()}-host",
                "name": asset_id,
                "type": "server",
                "owner": owner or "IT Security",
                "value": clamp(int(impact), 1, 5),
                "c": clamp(int(impact), 1, 5),
                "i": clamp(int(impact), 1, 5),
                "a": clamp(int(impact), 1, 5),
            },
        )

    threats_map = load_threats_csv(data_dir)
    control_map = load_control_map_csv(data_dir)
    treatments_map = load_treatments_csv(data_dir)

    t_info = threats_map.get(
        threat_id,
        {
            "threat_id": threat_id,
            "name": threat_id,
            "mitre_id": threat_id,
            "base_likelihood": clamp(int(likelihood), 1, 5),
            "primary_dimension": "C",
            "default_severity": severity if severity is not None else 4,
        },
    )
    ctrl_info = control_map.get(
        threat_id,
        {
            "nist_800_53": "RA-3",
            "cis_v8": "CIS 1",
            "control_name": "Risk Assessment & Mitigation",
        },
    )

    max_det_row = conn.execute("SELECT COALESCE(MAX(detection_id), 0) FROM detections").fetchone()
    next_det_id = int(max_det_row[0]) + 1

    host = asset_row["hostname"]
    resolved_owner = owner or asset_row.get("owner") or "IT Security"
    resolved_sev = int(severity) if severity is not None else int(t_info["default_severity"])
    resolved_vuln = vuln_desc.strip() if vuln_desc else get_default_vuln_for_threat(threat_id, data_dir)
    resolved_title = title.strip() if title.strip() else get_default_scenario_title(threat_id, asset_row["name"], source)
    resolved_summary = (
        summary.strip()
        if summary and summary.strip()
        else f"{resolved_title} on {host} ({asset_row['name']}) — {t_info['name']} + {resolved_vuln}"
    )
    resolved_treatment = (
        recommended_treatment.strip()
        if recommended_treatment and recommended_treatment.strip()
        else treatments_map.get(threat_id, "Implement compensating security controls and verify remediation.")
    )

    now_iso = "2026-11-10T10:15:00+05:30"
    details_payload = json.dumps(
        {
            "title": resolved_title,
            "summary": resolved_summary,
            "vuln_desc": resolved_vuln,
            "owner": resolved_owner,
            "status": status,
            "is_custom": True,
            "evidence_event_ids": [],
        }
    )

    l_clamped = clamp(int(likelihood), 1, 5)
    i_clamped = clamp(int(impact), 1, 5)
    freq_b = compute_frequency_bonus(threat_id, int(event_count))
    risk_val = l_clamped * i_clamped
    band_val = get_risk_band(risk_val)

    conn.execute(
        """
        INSERT INTO detections(
            detection_id, threat_id, host, asset_id, source, event_count, first_seen, last_seen, details
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            next_det_id,
            threat_id,
            host,
            asset_id,
            source,
            int(event_count),
            now_iso,
            now_iso,
            details_payload,
        ),
    )

    conn.execute(
        """
        INSERT INTO risk_scores(
            detection_id, impact, likelihood, freq_bonus, risk, band, severity, baseline_rank, risk_rank
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            next_det_id,
            i_clamped,
            l_clamped,
            freq_b,
            risk_val,
            band_val,
            resolved_sev,
            next_det_id,
            next_det_id,
        ),
    )

    # Insert indirect evidence records
    max_ev_row = conn.execute("SELECT COALESCE(MAX(evidence_id), 0) FROM evidence").fetchone()
    ev_id_1 = int(max_ev_row[0]) + 1
    ev_id_2 = ev_id_1 + 1

    conn.execute(
        """
        INSERT INTO evidence(
            evidence_id, detection_id, type, source_host, ts, description, log_event_id, control_nist, control_cis
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ev_id_1,
            next_det_id,
            "indirect",
            host,
            now_iso,
            f"Correlation conclusion: {resolved_summary}",
            None,
            ctrl_info["nist_800_53"],
            ctrl_info["cis_v8"],
        ),
    )
    conn.execute(
        """
        INSERT INTO evidence(
            evidence_id, detection_id, type, source_host, ts, description, log_event_id, control_nist, control_cis
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ev_id_2,
            next_det_id,
            "indirect",
            host,
            now_iso,
            f"Computed risk score record: Risk={risk_val} ({band_val}) [Likelihood L={l_clamped}, Impact I={i_clamped}]",
            None,
            ctrl_info["nist_800_53"],
            ctrl_info["cis_v8"],
        ),
    )

    # Insert corresponding issue record so status & actions complete track cleanly
    max_iss_row = conn.execute("SELECT COALESCE(MAX(issue_id), 0) FROM issues").fetchone()
    next_issue_id = int(max_iss_row[0]) + 1
    conn.execute(
        """
        INSERT INTO issues(
            issue_id, detection_id, title, asset_id, owner, control_nist, control_cis,
            risk_score, risk_band, evidence_ids, recommended_treatment, status, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            next_issue_id,
            next_det_id,
            f"{resolved_title} ({ctrl_info['nist_800_53']})",
            asset_id,
            resolved_owner,
            ctrl_info["nist_800_53"],
            ctrl_info["cis_v8"],
            risk_val,
            band_val,
            json.dumps([ev_id_1, ev_id_2]),
            resolved_treatment,
            status,
            now_iso,
        ),
    )

    recalculate_ranks_in_db(conn)
    return next_det_id


def update_risk_in_db(
    conn: sqlite3.Connection,
    detection_id: int,
    likelihood: int | None = None,
    impact: int | None = None,
    status: str | None = None,
    title: str | None = None,
    summary: str | None = None,
    vuln_desc: str | None = None,
    owner: str | None = None,
    asset_id: str | None = None,
    threat_id: str | None = None,
    event_count: int | None = None,
    severity: int | None = None,
    recommended_treatment: str | None = None,
    data_dir: Path | None = None,
) -> None:
    """Update an existing risk scenario's scores, metadata, or status and recompute rankings."""
    det_row = conn.execute("SELECT * FROM detections WHERE detection_id = ?", (detection_id,)).fetchone()
    score_row = conn.execute("SELECT * FROM risk_scores WHERE detection_id = ?", (detection_id,)).fetchone()
    if not det_row or not score_row:
        return

    det = dict(det_row)
    sc = dict(score_row)
    details_dict = parse_detection_details(det.get("details"))

    new_asset_id = asset_id if asset_id is not None else det["asset_id"]
    new_threat_id = threat_id if threat_id is not None else det["threat_id"]
    new_event_count = int(event_count) if event_count is not None else int(det["event_count"])

    asset_db = conn.execute("SELECT * FROM assets WHERE asset_id = ?", (new_asset_id,)).fetchone()
    new_host = asset_db["hostname"] if asset_db else det["host"]
    default_owner = asset_db["owner"] if asset_db else "IT Security"

    if title is not None:
        details_dict["title"] = title.strip()
    if summary is not None:
        details_dict["summary"] = summary.strip()
    if vuln_desc is not None:
        details_dict["vuln_desc"] = vuln_desc.strip()
    if owner is not None:
        details_dict["owner"] = owner.strip()
    if status is not None:
        details_dict["status"] = status

    new_l = clamp(int(likelihood), 1, 5) if likelihood is not None else int(sc["likelihood"])
    new_i = clamp(int(impact), 1, 5) if impact is not None else int(sc["impact"])
    new_sev = clamp(int(severity), 1, 5) if severity is not None else int(sc["severity"])
    new_freq = compute_frequency_bonus(new_threat_id, new_event_count)

    conn.execute(
        """
        UPDATE detections
        SET threat_id = ?, host = ?, asset_id = ?, event_count = ?, details = ?
        WHERE detection_id = ?
        """,
        (
            new_threat_id,
            new_host,
            new_asset_id,
            new_event_count,
            json.dumps(details_dict),
            detection_id,
        ),
    )

    conn.execute(
        """
        UPDATE risk_scores
        SET likelihood = ?, impact = ?, freq_bonus = ?, severity = ?
        WHERE detection_id = ?
        """,
        (new_l, new_i, new_freq, new_sev, detection_id),
    )

    # Sync with issues table
    issue_row = conn.execute("SELECT * FROM issues WHERE detection_id = ?", (detection_id,)).fetchone()
    resolved_owner = details_dict.get("owner") or default_owner
    if issue_row:
        new_iss_status = status if status is not None else issue_row["status"]
        new_iss_treat = (
            recommended_treatment.strip()
            if recommended_treatment is not None and recommended_treatment.strip()
            else issue_row["recommended_treatment"]
        )
        new_iss_title = (
            f"{details_dict['title']} ({issue_row['control_nist']})"
            if details_dict.get("title")
            else issue_row["title"]
        )
        conn.execute(
            """
            UPDATE issues
            SET title = ?, asset_id = ?, owner = ?, status = ?, recommended_treatment = ?
            WHERE detection_id = ?
            """,
            (new_iss_title, new_asset_id, resolved_owner, new_iss_status, new_iss_treat, detection_id),
        )
    elif status is not None or recommended_treatment is not None:
        control_map = load_control_map_csv(data_dir)
        treatments_map = load_treatments_csv(data_dir)
        ctrl_info = control_map.get(new_threat_id, {"nist_800_53": "RA-3", "cis_v8": "CIS 1"})
        max_iss_row = conn.execute("SELECT COALESCE(MAX(issue_id), 0) FROM issues").fetchone()
        next_issue_id = int(max_iss_row[0]) + 1
        iss_title = details_dict.get("title") or f"Risk scenario S{detection_id}"
        conn.execute(
            """
            INSERT INTO issues(
                issue_id, detection_id, title, asset_id, owner, control_nist, control_cis,
                risk_score, risk_band, evidence_ids, recommended_treatment, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                next_issue_id,
                detection_id,
                f"{iss_title} ({ctrl_info['nist_800_53']})",
                new_asset_id,
                resolved_owner,
                ctrl_info["nist_800_53"],
                ctrl_info["cis_v8"],
                new_l * new_i,
                get_risk_band(new_l * new_i),
                "[]",
                recommended_treatment or treatments_map.get(new_threat_id, "Apply security controls."),
                status or "Open",
                det["last_seen"],
            ),
        )

    recalculate_ranks_in_db(conn)


def delete_risk_from_db(conn: sqlite3.Connection, detection_id: int) -> None:
    """Delete a risk scenario and its associated scores, issues, and evidence from the database."""
    conn.execute("DELETE FROM issues WHERE detection_id = ?", (detection_id,))
    conn.execute("DELETE FROM evidence WHERE detection_id = ?", (detection_id,))
    conn.execute("DELETE FROM risk_scores WHERE detection_id = ?", (detection_id,))
    conn.execute("DELETE FROM detections WHERE detection_id = ?", (detection_id,))
    recalculate_ranks_in_db(conn)


def upsert_asset_in_db(
    conn: sqlite3.Connection,
    asset_id: str,
    hostname: str,
    name: str,
    asset_type: str,
    owner: str,
    value: int,
    c: int,
    i: int,
    a: int,
) -> None:
    """Insert or update an asset in the SQLite assets table."""
    conn.execute(
        """
        INSERT INTO assets(asset_id, hostname, name, type, owner, value, c, i, a)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(asset_id) DO UPDATE SET
            hostname = excluded.hostname,
            name = excluded.name,
            type = excluded.type,
            owner = excluded.owner,
            value = excluded.value,
            c = excluded.c,
            i = excluded.i,
            a = excluded.a
        """,
        (
            asset_id.strip(),
            hostname.strip(),
            name.strip(),
            asset_type.strip(),
            owner.strip(),
            clamp(int(value), 1, 5),
            clamp(int(c), 1, 5),
            clamp(int(i), 1, 5),
            clamp(int(a), 1, 5),
        ),
    )
    conn.commit()


def delete_asset_from_db(conn: sqlite3.Connection, asset_id: str) -> None:
    """Delete an asset from the SQLite assets table."""
    conn.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
    conn.commit()


def recalculate_scores_from_assets_and_exposure(
    conn: sqlite3.Connection,
    exposure_override: dict[str, dict[str, int]] | None = None,
    data_dir: Path | None = None,
) -> None:
    """Recompute L and I for all detections using current DB assets and exposure matrix, then re-rank."""
    asset_rows = conn.execute("SELECT * FROM assets").fetchall()
    assets_map: dict[str, dict[str, Any]] = {}
    for r in asset_rows:
        d = dict(r)
        d["C"] = int(d["c"])
        d["I"] = int(d["i"])
        d["A"] = int(d["a"])
        assets_map[d["asset_id"]] = d

    threats_map = load_threats_csv(data_dir)
    exposure_map = exposure_override if exposure_override is not None else load_exposure_csv(data_dir)

    det_rows = conn.execute("SELECT * FROM detections").fetchall()
    for d_row in det_rows:
        det = dict(d_row)
        det_id = int(det["detection_id"])
        a_id = det["asset_id"]
        t_id = det["threat_id"]
        if a_id in assets_map and t_id in threats_map:
            asset_obj = assets_map[a_id]
            threat_obj = threats_map[t_id]
            exp_val = exposure_map.get(a_id, {}).get(t_id, 3)
            scored = score_single_detection(det, asset_obj, threat_obj, exp_val)
            conn.execute(
                """
                UPDATE risk_scores
                SET impact = ?, likelihood = ?, freq_bonus = ?, severity = ?
                WHERE detection_id = ?
                """,
                (
                    scored["impact"],
                    scored["likelihood"],
                    scored["freq_bonus"],
                    scored["severity"],
                    det_id,
                ),
            )

    recalculate_ranks_in_db(conn)


def update_issue_in_db(
    conn: sqlite3.Connection,
    issue_id: int,
    title: str | None = None,
    owner: str | None = None,
    recommended_treatment: str | None = None,
    status: str | None = None,
    risk_score: int | None = None,
) -> None:
    """Update an issue row in the issues table and sync status to its parent detection if linked."""
    row = conn.execute("SELECT * FROM issues WHERE issue_id = ?", (issue_id,)).fetchone()
    if not row:
        return
    curr = dict(row)
    new_title = title.strip() if title is not None else curr["title"]
    new_owner = owner.strip() if owner is not None else curr["owner"]
    new_treat = recommended_treatment.strip() if recommended_treatment is not None else curr["recommended_treatment"]
    new_status = status if status is not None else curr["status"]
    new_score = int(risk_score) if risk_score is not None else int(curr["risk_score"])
    new_band = get_risk_band(new_score)

    conn.execute(
        """
        UPDATE issues
        SET title = ?, owner = ?, recommended_treatment = ?, status = ?, risk_score = ?, risk_band = ?
        WHERE issue_id = ?
        """,
        (new_title, new_owner, new_treat, new_status, new_score, new_band, issue_id),
    )

    det_id = curr.get("detection_id")
    if det_id and status is not None:
        det_row = conn.execute("SELECT details FROM detections WHERE detection_id = ?", (det_id,)).fetchone()
        if det_row:
            d_dict = parse_detection_details(det_row["details"])
            d_dict["status"] = status
            conn.execute(
                "UPDATE detections SET details = ? WHERE detection_id = ?",
                (json.dumps(d_dict), det_id),
            )
    conn.commit()


def delete_issue_from_db(conn: sqlite3.Connection, issue_id: int) -> None:
    """Delete an issue row from the issues table."""
    conn.execute("DELETE FROM issues WHERE issue_id = ?", (issue_id,))
    conn.commit()


