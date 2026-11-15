"""Risk scoring formulas, risk banding, baseline vs. risk ranking, and residual risk calculation."""

from datetime import datetime
import math
from pathlib import Path
import sqlite3
from typing import Any

from engine.db import (
    load_assets_csv,
    load_exposure_csv,
    load_threats_csv,
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
