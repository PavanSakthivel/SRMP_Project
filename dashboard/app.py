"""RiskSIEM Streamlit Dashboard built with the Dark SOC Executive Template (v3.4-PROD) & Interactive CRUD."""

import io
import json
from pathlib import Path
import sys

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from engine.chain import read_anchor, verify_chain
from engine.db import (
    ANCHOR_DIR,
    DATA_DIR,
    DEFAULT_DB_PATH,
    get_connection,
    load_assets_csv,
    load_control_map_csv,
    load_exposure_csv,
    load_threats_csv,
    load_treatments_csv,
    load_tv_pairs_csv,
    load_vulnerabilities_csv,
)
from engine.evidence import generate_audit_report_markdown
from engine.risk import (
    add_risk_to_db,
    clamp,
    compute_residual_score,
    delete_asset_from_db,
    delete_issue_from_db,
    delete_risk_from_db,
    get_default_scenario_title,
    get_default_vuln_for_threat,
    get_risk_band,
    parse_detection_details,
    recalculate_ranks_in_db,
    recalculate_scores_from_assets_and_exposure,
    score_single_detection,
    update_issue_in_db,
    update_risk_in_db,
    upsert_asset_in_db,
)
from scripts.reset_demo import reset_environment
from scripts.run_pipeline import run_pipeline
from scripts.tamper_demo import tamper_record

st.set_page_config(
    page_title="RiskSIEM | SOC Executive Risk & Audit Layer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject the Dark SOC v3.4-PROD Template CSS & Fonts across all pages
SOC_TEMPLATE_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

:root {
    --surface: #0c1322;
    --surface-lowest: #070e1d;
    --surface-low: #141b2b;
    --surface-container: #191f2f;
    --surface-high: #232a3a;
    --surface-highest: #2e3545;
    --on-surface: #dce2f7;
    --on-surface-variant: #c2c6d6;
    --outline: #8c909f;
    --primary: #adc6ff;
    --primary-container: #4d8eff;
    --on-primary: #002e6a;
    --secondary: #c0c1ff;
    --secondary-container: #3131c0;
    --tertiary: #4edea3;
    --tertiary-fixed: #6ffbbe;
    --error: #ffb4ab;
    --error-container: #93000a;
    --on-error-container: #ffdad6;
}

.stApp {
    background-color: var(--surface) !important;
    color: var(--on-surface) !important;
    font-family: 'Geist', -apple-system, BlinkMacSystemFont, sans-serif !important;
}

section[data-testid="stSidebar"] {
    background-color: var(--surface-low) !important;
    border-right: 1px solid #232a3a !important;
}

section[data-testid="stSidebar"] * {
    color: var(--on-surface);
}

.block-container {
    padding-top: 1.1rem !important;
    padding-bottom: 2.5rem !important;
    max-width: 1460px !important;
}

h1, h2, h3, h4 {
    color: var(--on-surface) !important;
    font-family: 'Geist', sans-serif !important;
    letter-spacing: -0.01em;
}

code, pre, .mono {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Top Global SOC Navbar (from screenshot) */
.soc-topbar {
    background: var(--surface-lowest);
    border: 1px solid #1e2638;
    border-radius: 0.6rem;
    padding: 0.5rem 1rem;
    margin-bottom: 1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.75rem;
}

.soc-topbar-pill {
    background: var(--surface-low);
    border: 1px solid #232a3a;
    border-radius: 0.35rem;
    padding: 0.25rem 0.65rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    color: var(--on-surface-variant);
    display: inline-flex;
    align-items: center;
    gap: 0.45rem;
}

/* Custom SOC Banner & Cards */
.soc-banner {
    background: var(--surface-low);
    border: 1px solid #232a3a;
    border-radius: 0.75rem;
    padding: 1.15rem 1.4rem;
    margin-bottom: 1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
}

.soc-badge-green {
    background: rgba(78, 222, 163, 0.12);
    color: var(--tertiary);
    border: 1px solid rgba(78, 222, 163, 0.3);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.64rem;
    font-weight: 700;
    padding: 0.15rem 0.5rem;
    border-radius: 0.25rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

.soc-kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.85rem;
    margin-bottom: 1.1rem;
}

@media (max-width: 1100px) {
    .soc-kpi-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

.soc-kpi-card {
    background: var(--surface-low);
    border: 1px solid #232a3a;
    border-radius: 0.75rem;
    padding: 1rem 1.15rem;
    position: relative;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    min-height: 128px;
}

.soc-kpi-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.66rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--outline);
    margin-bottom: 0.4rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.soc-kpi-value {
    font-size: 2.05rem;
    font-weight: 700;
    line-height: 2.25rem;
    margin-bottom: 0.45rem;
}

.soc-kpi-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    color: var(--on-surface-variant);
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.4rem;
}

.soc-panel {
    background: var(--surface-low);
    border: 1px solid #232a3a;
    border-radius: 0.75rem;
    padding: 1.15rem;
    margin-bottom: 1rem;
}

.soc-panel-header {
    background: var(--surface-container);
    padding: 0.75rem 1rem;
    border-radius: 0.5rem;
    margin-bottom: 0.85rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    border: 1px solid #232a3a;
}

/* SOC Table */
.soc-table-wrap {
    overflow-x: auto;
    border-radius: 0.5rem;
    border: 1px solid #232a3a;
}

table.soc-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
    background: var(--surface-low);
}

table.soc-table thead tr {
    background: #191f2f;
    color: var(--outline);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.66rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    border-bottom: 1px solid #232a3a;
}

table.soc-table th, table.soc-table td {
    padding: 0.65rem 0.7rem;
    text-align: left;
    border-bottom: 1px solid #1b2234;
}

table.soc-table tbody tr:hover {
    background: #1b2336;
}

.band-pill {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.64rem;
    font-weight: 700;
    padding: 0.16rem 0.5rem;
    border-radius: 0.25rem;
    text-transform: uppercase;
    display: inline-block;
    letter-spacing: 0.04em;
}

.band-critical {
    background: rgba(147, 0, 10, 0.45);
    color: #ffb4ab;
    border: 1px solid rgba(255, 180, 171, 0.35);
}

.band-high {
    background: rgba(49, 49, 192, 0.5);
    color: #e1e0ff;
    border: 1px solid rgba(192, 193, 255, 0.35);
}

.band-medium {
    background: rgba(31, 58, 61, 0.85);
    color: #6ffbbe;
    border: 1px solid rgba(111, 251, 190, 0.35);
}

.band-low {
    background: #191f2f;
    color: #adc6ff;
    border: 1px solid rgba(173, 198, 255, 0.25);
}

/* 5x5 Matrix HTML Grid (matching screenshot) */
.soc-matrix-wrap {
    display: grid;
    grid-template-columns: 22px 1fr;
    gap: 0.35rem;
    align-items: center;
}

.soc-matrix-ylabel {
    writing-mode: vertical-rl;
    transform: rotate(180deg);
    text-align: center;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.62rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    color: var(--outline);
    text-transform: uppercase;
}

.soc-matrix-row {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 0.35rem;
    margin-bottom: 0.35rem;
}

.soc-matrix-cell {
    height: 3.15rem;
    border-radius: 0.35rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    font-weight: 700;
    border: 1px solid rgba(255, 255, 255, 0.05);
    position: relative;
}

.soc-matrix-cell.cell-low {
    background: #182032;
    color: #8c909f;
}

.soc-matrix-cell.cell-med {
    background: #1c3338;
    color: #4edea3;
}

.soc-matrix-cell.cell-med.has-scen {
    border: 1px solid rgba(78, 222, 163, 0.55);
    background: #1f3c40;
}

.soc-matrix-cell.cell-high {
    background: #242754;
    color: #c0c1ff;
}

.soc-matrix-cell.cell-high.has-scen {
    border: 1px solid rgba(192, 193, 255, 0.65);
    background: #2d3070;
}

.soc-matrix-cell.cell-crit {
    background: #482329;
    color: #ffb4ab;
}

.soc-matrix-cell.cell-crit.has-scen {
    border: 2px solid #ffb4ab;
    background: #5b2830;
}

.soc-matrix-cell.active-cell {
    outline: 2px solid #adc6ff;
    box-shadow: 0 0 10px rgba(173, 198, 255, 0.35);
}

.soc-matrix-tag {
    font-size: 0.58rem;
    padding: 0.04rem 0.32rem;
    border-radius: 0.2rem;
    margin-top: 2px;
    background: #070e1d;
    color: #dce2f7;
    font-weight: 700;
    line-height: 1.1;
}

.soc-matrix-tag.crit-tag {
    background: #ffb4ab;
    color: #4a0e13;
}

/* Alert Cards */
.alert-grid-3 {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 0.85rem;
}

@media (max-width: 992px) {
    .alert-grid-3 {
        grid-template-columns: 1fr;
    }
}

.soc-alert-card {
    background: var(--surface-container);
    border-radius: 0.5rem;
    padding: 0.95rem 1.05rem;
    border: 1px solid #232a3a;
    border-left: 4px solid var(--error);
}

.soc-alert-card.secondary-border {
    border-left-color: var(--secondary);
}

/* Streamlit Buttons & Controls matching Dark SOC */
div.stButton > button, div.stDownloadButton > button {
    background-color: var(--surface-high) !important;
    color: var(--on-surface) !important;
    border: 1px solid #2e3545 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.74rem !important;
    border-radius: 0.4rem !important;
    transition: all 0.15s ease !important;
}

div.stButton > button:hover, div.stDownloadButton > button:hover {
    background-color: var(--primary-container) !important;
    color: #001a42 !important;
    border-color: var(--primary) !important;
}

div.stButton > button[kind="primary"] {
    background-color: #3b69b8 !important;
    color: #ffffff !important;
    border: 1px solid #adc6ff !important;
    font-weight: 700 !important;
}

div.stButton > button[kind="primary"]:hover {
    background-color: #4d8eff !important;
    color: #001a42 !important;
}
</style>
"""
st.markdown(SOC_TEMPLATE_CSS, unsafe_allow_html=True)


def ensure_db_ready() -> None:
    """Ensure riskSIEM.db exists and is populated before rendering."""
    if not DEFAULT_DB_PATH.exists():
        run_pipeline(verbose=False)
    else:
        conn = get_connection()
        try:
            cnt = conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='detections'"
            ).fetchone()[0]
            if cnt == 0:
                conn.close()
                run_pipeline(verbose=False)
        finally:
            try:
                conn.close()
            except Exception:
                pass


ensure_db_ready()

if "treated_ids" not in st.session_state:
    st.session_state["treated_ids"] = set()
if "band_filter" not in st.session_state:
    st.session_state["band_filter"] = "ALL"
if "hm_cell_filter" not in st.session_state:
    st.session_state["hm_cell_filter"] = None
if "show_add_risk_form" not in st.session_state:
    st.session_state["show_add_risk_form"] = False
if "show_manage_drawer" not in st.session_state:
    st.session_state["show_manage_drawer"] = False
if "editing_risk_id" not in st.session_state:
    st.session_state["editing_risk_id"] = None
if "selected_page" not in st.session_state:
    st.session_state["selected_page"] = "1. Overview & Risk Matrix"
if "custom_exposure" not in st.session_state:
    st.session_state["custom_exposure"] = load_exposure_csv()


def load_dashboard_state() -> dict:
    """Load detections, scores, evidence, issues, assets, and chain status from riskSIEM.db."""
    conn = get_connection()
    try:
        det_rows = conn.execute(
            """
            SELECT d.detection_id, d.threat_id, d.host, d.asset_id, d.source, d.event_count,
                   d.first_seen, d.last_seen, d.details,
                   COALESCE(a.name, d.asset_id) AS asset_name,
                   COALESCE(a.owner, 'IT Security') AS asset_owner,
                   COALESCE(a.value, 3) AS asset_value,
                   r.impact, r.likelihood, r.freq_bonus, r.risk, r.band, r.severity,
                   r.baseline_rank, r.risk_rank
            FROM detections d
            JOIN risk_scores r ON d.detection_id = r.detection_id
            LEFT JOIN assets a ON d.asset_id = a.asset_id
            ORDER BY r.risk_rank ASC, d.detection_id ASC
            """
        ).fetchall()

        asset_rows = conn.execute(
            "SELECT asset_id, hostname, name, type, owner, value, c, i, a FROM assets ORDER BY asset_id ASC"
        ).fetchall()

        ev_rows = conn.execute(
            """
            SELECT evidence_id, detection_id, type, source_host, ts, description,
                   log_event_id, control_nist, control_cis
            FROM evidence
            ORDER BY evidence_id ASC
            """
        ).fetchall()

        issue_rows = conn.execute(
            """
            SELECT issue_id, detection_id, title, asset_id, owner, control_nist, control_cis,
                   risk_score, risk_band, evidence_ids, recommended_treatment, status, created_at
            FROM issues
            ORDER BY risk_score DESC, issue_id ASC
            """
        ).fetchall()

        log_rows = conn.execute(
            """
            SELECT id, ts, host, program, event_type, src_ip, dst_port, username,
                   prev_hash, hash, raw_line
            FROM log_events
            ORDER BY id ASC
            """
        ).fetchall()

        chain_res = verify_chain(conn)
        anchor_data = read_anchor()
    finally:
        conn.close()

    return {
        "detections": [dict(r) for r in det_rows],
        "assets": [dict(r) for r in asset_rows],
        "evidence": [dict(r) for r in ev_rows],
        "issues": [dict(r) for r in issue_rows],
        "logs": [dict(r) for r in log_rows],
        "chain": chain_res,
        "anchor": anchor_data,
    }


state = load_dashboard_state()
chain_info = state["chain"]
head_hash = chain_info.get("head_hash", "0" * 64)
short_head = f"{head_hash[:8]}...{head_hash[-6:]}"
sync_color = "#4edea3" if chain_info["ok"] else "#ffb4ab"
sync_label = "SYNCED" if chain_info["ok"] else "TAMPERED"
db_status_text = "Database Synced" if chain_info["ok"] else "Chain Tampered"

PAGES = [
    "1. Overview & Risk Matrix",
    "2. Methodology & Catalogs",
    "3. Audit Evidence & Issues",
    "4. Tamper-Evident Log Chain",
    "5. Baseline vs Validation",
    "6. Audit Report Generator",
]

# --- SIDEBAR (Exact v3.4-PROD Template Aesthetic) ---
with st.sidebar:
    st.markdown(
        f"""
        <div style="display:flex; flex-direction:column; gap:0.25rem; margin-bottom:0.85rem;">
            <div style="display:flex; align-items:center; gap:0.5rem;">
                <span style="width:10px; height:10px; border-radius:50%; background:{sync_color}; display:inline-block;"></span>
                <span style="font-size:1.15rem; font-weight:700; color:#adc6ff; letter-spacing:0.02em;">RISKSIEM</span>
                <span style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; background:#232a3a; color:#d8e2ff; padding:2px 6px; border-radius:4px; font-weight:700; border:1px solid #2e3545;">v3.4-PROD</span>
            </div>
            <div style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:#c2c6d6;">Greenfield Institute of Technology</div>
            <div style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:#8c909f; font-weight:700;">SEC-CODE: 21CSC308T / SOC-LAB</div>
        </div>
        <div style="background:#070e1d; border:1px solid #232a3a; border-radius:0.5rem; padding:0.6rem 0.75rem; margin-bottom:1rem;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.2rem;">
                <span style="font-family:'JetBrains Mono',monospace; font-size:0.64rem; font-weight:700; color:{sync_color};">● {sync_label}</span>
                <span style="font-family:'JetBrains Mono',monospace; font-size:0.64rem; color:#8c909f;">SHA-256</span>
            </div>
            <div style="font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#c2c6d6;">HEAD: {short_head}</div>
        </div>
        <div style="font-family:'JetBrains Mono',monospace; font-size:0.64rem; color:#8c909f; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; margin-bottom:0.35rem;">
            Navigation Modules
        </div>
        """,
        unsafe_allow_html=True,
    )

    curr_idx = PAGES.index(st.session_state["selected_page"]) if st.session_state["selected_page"] in PAGES else 0
    selected_page = st.radio(
        "Navigation Modules",
        PAGES,
        index=curr_idx,
        label_visibility="collapsed",
    )
    if selected_page != st.session_state["selected_page"]:
        st.session_state["selected_page"] = selected_page
        st.rerun()

    st.markdown(
        """
        <div style="font-family:'JetBrains Mono',monospace; font-size:0.64rem; color:#8c909f; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; margin-top:1.1rem; margin-bottom:0.4rem;">
            Quick Actions
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("➕ Add New Risk Scenario", use_container_width=True, type="primary"):
        st.session_state["selected_page"] = "1. Overview & Risk Matrix"
        st.session_state["show_add_risk_form"] = True
        st.rerun()

    if st.button("🛡️ Anchor Ledger / Verify (ALT+A)", use_container_width=True):
        st.session_state["selected_page"] = "4. Tamper-Evident Log Chain"
        st.rerun()

    if st.button("🔄 Re-verify & Reset (CTRL+R)", use_container_width=True):
        reset_environment(verbose=False)
        st.session_state["treated_ids"] = set()
        st.session_state["hm_cell_filter"] = None
        st.session_state["band_filter"] = "ALL"
        st.session_state["editing_risk_id"] = None
        st.session_state["show_add_risk_form"] = False
        st.session_state["custom_exposure"] = load_exposure_csv()
        st.rerun()

    if st.button("🔒 Load AC-7 Lockout Log", use_container_width=True):
        run_pipeline(log_path=DATA_DIR / "sample" / "auth_with_lockout.log", verbose=False)
        st.session_state["treated_ids"] = set()
        st.session_state["hm_cell_filter"] = None
        st.rerun()

    if st.button("✳️ Trigger Tamper Demo (F9)", use_container_width=True):
        try:
            tamper_record(record_id=150)
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))

    st.markdown(
        f"""
        <div style="margin-top:1rem; padding:0.55rem 0.75rem; background:#070e1d; border:1px solid #232a3a; border-radius:0.4rem; display:flex; justify-content:space-between; align-items:center;">
            <span style="font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#c2c6d6;">▣ SecOps Instance: 04</span>
            <span style="width:8px; height:8px; border-radius:50%; background:{sync_color}; display:inline-block;"></span>
        </div>
        """,
        unsafe_allow_html=True,
    )


# --- TOP GLOBAL SOC STATUS BAR (Shown on every page) ---
st.markdown(
    f"""
    <div class="soc-topbar">
        <div style="display:flex; align-items:center; gap:0.6rem; flex-wrap:wrap;">
            <div class="soc-topbar-pill">
                <span style="color:{sync_color};">🔒 Status: <strong>{db_status_text}</strong></span>
                <span style="color:#8c909f;">|</span>
                <span>SHA-256 Head Anchored</span>
            </div>
            <div class="soc-topbar-pill">
                <span style="color:#adc6ff;">🎓 GREENFIELD TECH 21CSC308T</span>
            </div>
        </div>
        <div style="display:flex; align-items:center; gap:0.55rem;">
            <div class="soc-topbar-pill">
                <span>🔍 Telemetry Query</span>
                <span style="background:#232a3a; padding:1px 5px; border-radius:3px; font-size:0.6rem; color:#adc6ff;">⌘K</span>
            </div>
            <div class="soc-topbar-pill" style="padding:0.25rem 0.5rem;">🛡️</div>
            <div class="soc-topbar-pill" style="padding:0.25rem 0.5rem;">🔔</div>
            <div class="soc-topbar-pill" style="background:#adc6ff; color:#002e6a; font-weight:700; border-radius:50%; width:26px; height:26px; justify-content:center; padding:0;">👤</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


def render_band_pill(band: str) -> str:
    b = band.upper()
    cls = "band-low"
    if b == "CRITICAL":
        cls = "band-critical"
    elif b == "HIGH":
        cls = "band-high"
    elif b == "MEDIUM":
        cls = "band-medium"
    return f'<span class="band-pill {cls}">{b}</span>'


# =====================================================================
# PAGE 1: OVERVIEW & RISK MATRIX (WITH FULL ADD / MODIFY / DELETE CRUD)
# =====================================================================
if selected_page == "1. Overview & Risk Matrix":
    detections = state["detections"]
    issues = state["issues"]
    assets_list = state["assets"]
    assets_by_id = {a["asset_id"]: a for a in assets_list}
    threats_map = load_threats_csv()
    exposure_map = st.session_state["custom_exposure"]
    treatments_map = load_treatments_csv()

    issues_by_det: dict[int, dict] = {}
    for iss in issues:
        if iss.get("detection_id") is not None:
            issues_by_det[int(iss["detection_id"])] = iss

    treated_ids: set[int] = st.session_state["treated_ids"]
    display_rows = []
    for d in detections:
        det_id = int(d["detection_id"])
        t_id = d["threat_id"]
        a_id = d["asset_id"]
        t_info = threats_map.get(
            t_id,
            {
                "threat_id": t_id,
                "name": t_id,
                "mitre_id": t_id,
                "base_likelihood": int(d["likelihood"]),
                "primary_dimension": "C",
                "default_severity": int(d["severity"]),
            },
        )
        a_info = assets_by_id.get(
            a_id,
            {
                "asset_id": a_id,
                "hostname": d["host"],
                "name": d.get("asset_name") or a_id,
                "owner": d.get("asset_owner") or "IT Security",
                "value": int(d.get("asset_value") or 3),
                "c": 3,
                "i": 3,
                "a": 3,
            },
        )
        a_norm = {
            **a_info,
            "C": int(a_info.get("C", a_info.get("c", 3))),
            "I": int(a_info.get("I", a_info.get("i", 3))),
            "A": int(a_info.get("A", a_info.get("a", 3))),
        }

        details_dict = parse_detection_details(d.get("details"))
        linked_issue = issues_by_det.get(det_id)

        title_str = details_dict.get("title") or get_default_scenario_title(t_id, a_norm["name"], d.get("source", ""))
        vuln_str = details_dict.get("vuln_desc") or get_default_vuln_for_threat(t_id)
        owner_str = (
            details_dict.get("owner")
            or (linked_issue["owner"] if linked_issue else None)
            or a_norm.get("owner")
            or "IT Security"
        )
        status_str = (
            details_dict.get("status")
            or (linked_issue["status"] if linked_issue else None)
            or "Open"
        )
        treatment_str = (
            (linked_issue["recommended_treatment"] if linked_issue else None)
            or treatments_map.get(t_id, "Apply security control remediation.")
        )

        orig_exp = exposure_map.get(a_id, {}).get(t_id, 3)
        residual = compute_residual_score(d, a_norm, t_info, orig_exp)
        is_treated = det_id in treated_ids or status_str in ("Implemented", "Verified")
        active_l = residual["likelihood"] if det_id in treated_ids else int(d["likelihood"])
        active_risk = residual["risk"] if det_id in treated_ids else int(d["risk"])
        active_band = residual["band"] if det_id in treated_ids else d["band"]
        shift = int(d["baseline_rank"]) - int(d["risk_rank"])

        display_rows.append(
            {
                **d,
                "title": title_str,
                "vuln_desc": vuln_str,
                "owner": owner_str,
                "status": status_str,
                "recommended_treatment": treatment_str,
                "threat_name": t_info["name"],
                "orig_exposure": orig_exp,
                "residual_l": residual["likelihood"],
                "residual_risk": residual["risk"],
                "residual_band": residual["band"],
                "is_treated": is_treated,
                "active_l": active_l,
                "active_risk": active_risk,
                "active_band": active_band,
                "shift": shift,
            }
        )

    crit_list = [f"S{r['detection_id']}: {r['host']}" for r in display_rows if r["active_band"] == "Critical"]
    high_list = [f"S{r['detection_id']}" for r in display_rows if r["active_band"] == "High"]
    med_list = [f"S{r['detection_id']}" for r in display_rows if r["active_band"] == "Medium"]
    low_list = [f"S{r['detection_id']}" for r in display_rows if r["active_band"] == "Low"]

    chain_ok = chain_info["ok"]
    chain_title = "INTACT (VALID)" if chain_ok else f"TAMPERED (ID {chain_info['first_broken_id']})"
    chain_color = "#4edea3" if chain_ok else "#ffb4ab"
    chain_badge = "ANCHOR OK" if chain_ok else "CHAIN BROKEN"

    # --- Top Executive Banner (with Reset Simulation & Add Risk buttons) ---
    st.markdown(
        f"""
        <div class="soc-banner">
            <div>
                <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.35rem;">
                    <span class="soc-badge-green">SOC STAGE: ACTIVE TRIAGE</span>
                    <span style="color:#8c909f;">•</span>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:#c2c6d6;">Course 21CSC308T / Real-Time Audit Core</span>
                </div>
                <div style="font-size:1.6rem; font-weight:700; color:#dce2f7; letter-spacing:-0.01em;">RiskSIEM Executive Risk & Threat Overview</div>
                <div style="font-size:0.84rem; color:#c2c6d6;">Real-time contextual cyber risk ranking on ingested auth & telemetry logs (Greenfield Institute of Technology)</div>
            </div>
            <div style="display:flex; flex-direction:column; align-items:flex-end; gap:0.4rem;">
                <div style="background:#070e1d; border:1px solid #232a3a; padding:0.35rem 0.75rem; border-radius:0.4rem; font-family:'JetBrains Mono',monospace; font-size:0.7rem;">
                    <span style="color:{sync_color};">●</span> Feed Ingest: <strong>Active</strong> | <span style="color:#adc6ff;">08:16:16 UTC ({len(state['logs'])} events)</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # --- 4 KPI Cards (Exact Screenshot Layout) ---
    crit_sub = ", ".join(crit_list) if crit_list else "None active"
    hm_summary = f"High: {', '.join(high_list) or '0'} • Med: {', '.join(med_list) or '0'}" + (
        f" • Low: {', '.join(low_list)}" if low_list else ""
    )
    triage_cases_cnt = len(high_list) + len(med_list) + len(low_list)
    st.markdown(
        f"""
        <div class="soc-kpi-grid">
            <div class="soc-kpi-card" style="border-bottom: 3px solid #4d8eff;">
                <div class="soc-kpi-title">
                    <span>INGESTED DETECTIONS</span>
                    <span style="color:#8c909f; font-size:0.85rem;">⊞</span>
                </div>
                <div class="soc-kpi-value" style="color:#adc6ff;">
                    {len(display_rows)} <span style="font-size:0.74rem; font-family:'JetBrains Mono',monospace; color:#4edea3; font-weight:500;">100% Evaluated</span>
                </div>
                <div class="soc-kpi-sub">
                    <span>Unmapped: 0 telemetry</span>
                    <span class="soc-badge-green">COMPLETE</span>
                </div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #ffb4ab;">
                <div class="soc-kpi-title" style="color:#ffb4ab;">
                    <span>CRITICAL RISK ALERTS</span>
                    <span style="color:#ffb4ab; font-size:0.85rem;">①</span>
                </div>
                <div class="soc-kpi-value" style="color:#ffb4ab;">
                    {len(crit_list)} <span style="font-size:0.74rem; font-family:'JetBrains Mono',monospace; color:#ffb4ab; font-weight:500;">Band 20-25</span>
                </div>
                <div class="soc-kpi-sub">
                    <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{crit_sub}</span>
                    <span style="background:#93000a; color:#ffdad6; font-size:0.58rem; padding:2px 6px; border-radius:3px; font-weight:700; white-space:nowrap;">CONTAIN IMMEDIATE</span>
                </div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #c0c1ff;">
                <div class="soc-kpi-title">
                    <span>HIGH / MEDIUM ALERTS</span>
                    <span style="color:#8c909f; font-size:0.85rem;">⏱</span>
                </div>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.35rem;">
                    <div class="soc-kpi-value" style="color:#dce2f7; margin-bottom:0;">{len(high_list)}H / {len(med_list)}M</div>
                    <div style="font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#8c909f; text-align:right;">{triage_cases_cnt} Triage<br>Cases</div>
                </div>
                <div class="soc-kpi-sub">
                    <span style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{hm_summary}</span>
                    <span style="background:#232a3a; color:#e1e0ff; font-size:0.58rem; padding:2px 6px; border-radius:3px; font-weight:700;">STAGED</span>
                </div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid {chain_color};">
                <div class="soc-kpi-title" style="color:{chain_color};">
                    <span>SHA-256 LOG INTEGRITY</span>
                    <span style="color:{chain_color}; font-size:0.85rem;">🛡️</span>
                </div>
                <div class="soc-kpi-value" style="color:{chain_color}; font-size:1.35rem;">{chain_title}</div>
                <div class="soc-kpi-sub">
                    <span>{chain_info['checked']} Blocks Verified</span>
                    <span style="background:rgba(78,222,163,0.12); color:{chain_color}; border:1px solid rgba(78,222,163,0.3); font-size:0.58rem; padding:2px 6px; border-radius:3px; font-weight:700;">{chain_badge}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # --- Middle Section: Left (Risk-Ranked Detection Queue + Interactive CRUD) | Right (5x5 Risk Matrix) ---
    col_left, col_right = st.columns([8, 4], gap="medium")

    with col_left:
        # Action & Filter Bar above the Risk-Ranked Detection Queue
        act_c1, act_c2, act_c3, act_c4 = st.columns([4.2, 2.2, 2.2, 1.9], vertical_alignment="center")
        with act_c1:
            band_choice = st.segmented_control(
                "Filter view",
                options=["ALL", "Critical", "High", "Medium", "Low"],
                default=st.session_state["band_filter"],
                label_visibility="collapsed",
            )
            if band_choice and band_choice != st.session_state["band_filter"]:
                st.session_state["band_filter"] = band_choice
                st.rerun()
        with act_c2:
            add_lbl = "✕ Close Add Form" if st.session_state["show_add_risk_form"] else "➕ Add Risk"
            if st.button(add_lbl, use_container_width=True, type="primary", key="btn_open_add"):
                st.session_state["show_add_risk_form"] = not st.session_state["show_add_risk_form"]
                st.rerun()
        with act_c3:
            mod_lbl = "✕ Close Editor" if st.session_state["show_manage_drawer"] else "✏️ Modify / Delete Risks"
            if st.button(mod_lbl, use_container_width=True, key="btn_open_manage"):
                st.session_state["show_manage_drawer"] = not st.session_state["show_manage_drawer"]
                st.rerun()
        with act_c4:
            if st.button("🔄 Reset Simulation", use_container_width=True, key="btn_reset_sim"):
                reset_environment(verbose=False)
                st.session_state["treated_ids"] = set()
                st.session_state["hm_cell_filter"] = None
                st.session_state["band_filter"] = "ALL"
                st.session_state["editing_risk_id"] = None
                st.rerun()

        # --- INTERACTIVE ADD NEW RISK FORM ---
        if st.session_state["show_add_risk_form"]:
            with st.container(border=True):
                st.markdown("#### ➕ Add New Risk Detection to Queue")
                af_1, af_2 = st.columns(2)
                with af_1:
                    new_title = st.text_input(
                        "Scenario / Threat Description *",
                        value="Phished administrator credentials",
                    )
                    asset_choices = {
                        f"{a['asset_id']} • {a['hostname']} ({a['name']})": a["asset_id"]
                        for a in assets_list
                    }
                    asset_choices["➕ Custom Asset / Host..."] = "CUSTOM"
                    chosen_asset_lbl = st.selectbox("Target Asset / Host", list(asset_choices.keys()))
                    chosen_asset_id = asset_choices[chosen_asset_lbl]

                    if chosen_asset_id == "CUSTOM":
                        ca_col1, ca_col2 = st.columns(2)
                        with ca_col1:
                            custom_asset_name = st.text_input("Custom Asset Name", value="Authentication Service")
                        with ca_col2:
                            custom_host = st.text_input("Custom Hostname", value="auth-srv-01")
                        custom_owner = st.text_input("Asset Owner", value="IT Security")
                    else:
                        custom_asset_name = assets_by_id[chosen_asset_id]["name"]
                        custom_host = assets_by_id[chosen_asset_id]["hostname"]
                        custom_owner = st.text_input("Asset Owner", value=assets_by_id[chosen_asset_id]["owner"])

                with af_2:
                    threat_choices = {
                        f"{tid} — {t['name']} (MITRE {t['mitre_id']})": tid
                        for tid, t in threats_map.items()
                    }
                    chosen_threat_lbl = st.selectbox("Threat & MITRE Technique", list(threat_choices.keys()))
                    chosen_threat_id = threat_choices[chosen_threat_lbl]
                    new_vuln = st.text_input(
                        "Vulnerability / Control Weakness",
                        value=get_default_vuln_for_threat(chosen_threat_id),
                    )
                    new_status = st.selectbox(
                        "Initial Triage Status",
                        options=["Open", "In treatment", "Implemented", "Verified"],
                        index=0,
                    )

                if chosen_asset_id != "CUSTOM" and chosen_asset_id in assets_by_id:
                    a_obj = assets_by_id[chosen_asset_id]
                    a_norm = {
                        **a_obj,
                        "C": int(a_obj.get("c", 3)),
                        "I": int(a_obj.get("i", 3)),
                        "A": int(a_obj.get("a", 3)),
                    }
                    exp_def = exposure_map.get(chosen_asset_id, {}).get(chosen_threat_id, 4)
                    calc_prev = score_single_detection(
                        {"detection_id": 0, "event_count": 12},
                        a_norm,
                        threats_map[chosen_threat_id],
                        exp_def,
                    )
                    sug_l, sug_i = int(calc_prev["likelihood"]), int(calc_prev["impact"])
                else:
                    sug_l, sug_i = 4, 4

                sc_1, sc_2, sc_3, sc_4 = st.columns(4)
                with sc_1:
                    new_l = st.selectbox("Likelihood L (1–5)", options=[1, 2, 3, 4, 5], index=sug_l - 1)
                with sc_2:
                    new_i = st.selectbox("Impact I (1–5)", options=[1, 2, 3, 4, 5], index=sug_i - 1)
                with sc_3:
                    new_cnt = st.number_input("Events (n)", min_value=1, max_value=10000, value=12, step=1)
                with sc_4:
                    new_sev = st.selectbox(
                        "Severity (1–5)",
                        options=[1, 2, 3, 4, 5],
                        index=int(threats_map[chosen_threat_id]["default_severity"]) - 1,
                    )

                new_treat = st.text_input(
                    "Recommended Treatment",
                    value=treatments_map.get(chosen_threat_id, "Enforce MFA and least privilege access controls."),
                )
                prev_r = int(new_l) * int(new_i)
                prev_b = get_risk_band(prev_r)
                st.markdown(
                    f'<div style="font-family:\'JetBrains Mono\',monospace; font-size:0.78rem; color:#c2c6d6; margin-bottom:0.5rem;">'
                    f'Computed Risk (L×I): <strong style="color:#adc6ff;">{prev_r}</strong> ({new_l}×{new_i}) • Band: {render_band_pill(prev_b)}</div>',
                    unsafe_allow_html=True,
                )

                sv_c1, sv_c2, _ = st.columns([2.5, 2, 5.5])
                with sv_c1:
                    if st.button("✅ Save Risk to Queue", type="primary", use_container_width=True):
                        conn = get_connection()
                        try:
                            target_aid = chosen_asset_id
                            if chosen_asset_id == "CUSTOM":
                                target_aid = f"A{len(assets_list) + 1}"
                                upsert_asset_in_db(
                                    conn,
                                    asset_id=target_aid,
                                    hostname=custom_host,
                                    name=custom_asset_name,
                                    asset_type="service",
                                    owner=custom_owner,
                                    value=int(new_i),
                                    c=int(new_i),
                                    i=int(new_i),
                                    a=int(new_i),
                                )
                            add_risk_to_db(
                                conn,
                                title=new_title,
                                asset_id=target_aid,
                                threat_id=chosen_threat_id,
                                likelihood=int(new_l),
                                impact=int(new_i),
                                event_count=int(new_cnt),
                                severity=int(new_sev),
                                source="soc-analyst",
                                status=new_status,
                                vuln_desc=new_vuln,
                                owner=custom_owner,
                                recommended_treatment=new_treat,
                            )
                        finally:
                            conn.close()
                        st.session_state["show_add_risk_form"] = False
                        st.rerun()
                with sv_c2:
                    if st.button("Cancel", use_container_width=True, key="cancel_add_risk"):
                        st.session_state["show_add_risk_form"] = False
                        st.rerun()

        # --- INTERACTIVE MODIFY / DELETE RISKS DRAWER ---
        if st.session_state["show_manage_drawer"]:
            with st.container(border=True):
                st.markdown("#### ✏️ Modify or Remove Risks in Queue")
                st.caption(
                    "Adjust Likelihood (L), Impact (I), Events, Severity, Status, or Scenario Title for any risk, or click **✕ Delete** to remove it from the register."
                )
                STATUS_LIST = ["Open", "In treatment", "Implemented", "Verified"]
                for r in display_rows:
                    det_id = int(r["detection_id"])
                    curr_l = int(r["likelihood"])
                    curr_i = int(r["impact"])
                    curr_stat = r["status"] if r["status"] in STATUS_LIST else "Open"

                    mc_1, mc_2, mc_3, mc_4, mc_5, mc_6, mc_7 = st.columns(
                        [1.1, 2.8, 1.1, 1.1, 1.5, 1.1, 0.9],
                        vertical_alignment="center",
                    )
                    with mc_1:
                        st.markdown(
                            f"<div style='font-family:JetBrains Mono,monospace; font-weight:700; color:#adc6ff;'>S{det_id} • {r['host']}</div>"
                            f"<div style='font-family:JetBrains Mono,monospace; font-size:0.68rem; color:#8c909f;'>Rank #{r['risk_rank']} (R={r['risk']})</div>",
                            unsafe_allow_html=True,
                        )
                    with mc_2:
                        new_t_val = st.text_input(
                            f"Title S{det_id}",
                            value=r["title"],
                            key=f"m_title_{det_id}",
                            label_visibility="collapsed",
                        )
                    with mc_3:
                        new_l_val = st.selectbox(
                            f"L S{det_id}",
                            options=[1, 2, 3, 4, 5],
                            index=clamp(curr_l, 1, 5) - 1,
                            format_func=lambda v: f"L = {v}",
                            key=f"m_l_{det_id}_{curr_l}",
                            label_visibility="collapsed",
                        )
                    with mc_4:
                        new_i_val = st.selectbox(
                            f"I S{det_id}",
                            options=[1, 2, 3, 4, 5],
                            index=clamp(curr_i, 1, 5) - 1,
                            format_func=lambda v: f"I = {v}",
                            key=f"m_i_{det_id}_{curr_i}",
                            label_visibility="collapsed",
                        )
                    with mc_5:
                        new_s_val = st.selectbox(
                            f"Status S{det_id}",
                            options=STATUS_LIST,
                            index=STATUS_LIST.index(curr_stat),
                            key=f"m_stat_{det_id}_{curr_stat}",
                            label_visibility="collapsed",
                        )
                    with mc_6:
                        if st.button("💾 Save", key=f"m_save_{det_id}", use_container_width=True):
                            conn = get_connection()
                            try:
                                update_risk_in_db(
                                    conn,
                                    detection_id=det_id,
                                    likelihood=int(new_l_val),
                                    impact=int(new_i_val),
                                    status=new_s_val,
                                    title=new_t_val,
                                )
                            finally:
                                conn.close()
                            st.rerun()
                    with mc_7:
                        if st.button("✕", key=f"m_del_{det_id}", help=f"Remove S{det_id}", use_container_width=True):
                            conn = get_connection()
                            try:
                                delete_risk_from_db(conn, detection_id=det_id)
                            finally:
                                conn.close()
                            st.rerun()

                    # Instant auto-save if L, I, or Status dropdown changed
                    if int(new_l_val) != curr_l or int(new_i_val) != curr_i or new_s_val != curr_stat:
                        conn = get_connection()
                        try:
                            update_risk_in_db(
                                conn,
                                detection_id=det_id,
                                likelihood=int(new_l_val),
                                impact=int(new_i_val),
                                status=new_s_val,
                                title=new_t_val,
                            )
                        finally:
                            conn.close()
                        st.rerun()

        # Filter display_rows by Band and Heat Map Cell
        filtered_rows = []
        for r in display_rows:
            if st.session_state["hm_cell_filter"] is not None:
                fl, fi = st.session_state["hm_cell_filter"]
                if (int(r["active_l"]), int(r["impact"])) != (fl, fi):
                    continue
            if st.session_state["band_filter"] != "ALL":
                if r["active_band"].lower() != st.session_state["band_filter"].lower():
                    continue
            filtered_rows.append(r)

        if st.session_state["hm_cell_filter"] is not None:
            fl, fi = st.session_state["hm_cell_filter"]
            if st.button(f"✕ Clear Matrix Cell Filter (L={fl}, I={fi})", key="clr_cell_btn"):
                st.session_state["hm_cell_filter"] = None
                st.rerun()

        # Build the Dark SOC Risk-Ranked Detection Queue Table (Exact Screenshot Style)
        table_rows_html = []
        for r in filtered_rows:
            rank_bg = "#93000a" if r["risk_rank"] <= 2 else "#232a3a"
            rank_fg = "#ffdad6" if r["risk_rank"] <= 2 else "#dce2f7"
            sev_color = "#ffb4ab" if int(r["severity"]) >= 4 else "#c2c6d6"

            if r["detection_id"] in treated_ids:
                l_cell = f'<span style="color:#8c909f; text-decoration:line-through;">{r["likelihood"]}</span>→<strong style="color:#4edea3;">{r["residual_l"]}</strong>'
                risk_cell = f'<strong style="color:#4edea3; font-size:0.95rem;">{r["residual_risk"]}</strong>'
                band_cell = render_band_pill(r["residual_band"])
            else:
                l_cell = f'{r["active_l"]}'
                risk_color = "#ffb4ab" if r["active_risk"] >= 20 else ("#dce2f7" if r["active_risk"] >= 12 else "#4edea3")
                risk_cell = f'<strong style="color:{risk_color}; font-size:0.95rem;">{r["active_risk"]}</strong>'
                band_cell = render_band_pill(r["active_band"])

            status_badge_color = (
                "#4edea3"
                if r["status"] == "Verified"
                else ("#adc6ff" if r["status"] in ("In treatment", "Implemented") else "#8c909f")
            )

            table_rows_html.append(
                f"<tr>"
                f'<td><span style="display:inline-flex; align-items:center; justify-content:center; width:24px; height:24px; border-radius:4px; background:{rank_bg}; color:{rank_fg}; font-family:\'JetBrains Mono\',monospace; font-size:0.74rem; font-weight:700;">{r["risk_rank"]}</span></td>'
                f'<td><div style="font-family:\'JetBrains Mono\',monospace; font-weight:700; color:#dce2f7;">S{r["detection_id"]} • {r["host"]}</div><div style="font-size:0.74rem; color:#8c909f;">{r["asset_name"]} — {r["title"]}</div></td>'
                f'<td><div style="font-family:\'JetBrains Mono\',monospace; color:#adc6ff; font-weight:600;">{r["threat_id"]}</div><div style="font-size:0.73rem; color:#8c909f;">{r["threat_name"]}</div></td>'
                f'<td style="text-align:right; font-family:\'JetBrains Mono\',monospace; font-weight:600;">{r["event_count"]}</td>'
                f'<td style="text-align:center; font-family:\'JetBrains Mono\',monospace; font-weight:700; color:{sev_color};">{r["severity"]}</td>'
                f'<td style="text-align:center; font-family:\'JetBrains Mono\',monospace;">{l_cell}</td>'
                f'<td style="text-align:center; font-family:\'JetBrains Mono\',monospace;">{r["impact"]}</td>'
                f'<td style="text-align:right; font-family:\'JetBrains Mono\',monospace;">{risk_cell}</td>'
                f"<td>{band_cell}</td>"
                f'<td style="font-family:\'JetBrains Mono\',monospace; font-size:0.7rem; color:{status_badge_color};">{r["status"]}</td>'
                f"</tr>"
            )

        st.markdown(
            f"""
            <div class="soc-panel">
                <div class="soc-panel-header">
                    <div style="display:flex; align-items:center; gap:0.55rem;">
                        <span style="color:#adc6ff; font-weight:700;">☰</span>
                        <span style="font-size:1.08rem; font-weight:700; color:#dce2f7;">Risk-Ranked Detection Queue</span>
                        <span style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; background:#232a3a; color:#adc6ff; padding:2px 7px; border-radius:4px; font-weight:700; border:1px solid #2e3545;">DYNAMIC SORT (L × I)</span>
                    </div>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:#4edea3;">Algorithm: GIT-RiskMatrix-v3</span>
                </div>
                <div class="soc-table-wrap">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>RANK</th>
                                <th>SCENARIO / ASSET</th>
                                <th>THREAT & MITRE</th>
                                <th style="text-align:right;">EVENTS</th>
                                <th style="text-align:center;">SEV</th>
                                <th style="text-align:center;">L</th>
                                <th style="text-align:center;">I</th>
                                <th style="text-align:right;">RISK (L×I)</th>
                                <th>BAND</th>
                                <th>STATUS</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(table_rows_html)}
                        </tbody>
                    </table>
                </div>
                <div style="margin-top:0.65rem; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#8c909f;">
                    <span>* L (Likelihood: 1-5) × I (Asset Impact: 1-5). Contextual scoring shifts baseline static severity.</span>
                    <span style="color:#4edea3;">Algorithm: GIT-RiskMatrix-v3</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Quick Inline Row Selector for Fast Single-Row Edit/Treatment/Delete right under Queue
        with st.expander("⚡ Quick Inline Risk Editor & Residual Risk Treatment (Add / Edit / Treat / Delete)", expanded=False):
            q_col1, q_col2 = st.columns([5, 5])
            with q_col1:
                treat_options = {
                    f"S{r['detection_id']} • {r['host']} ({r['threat_id']})": int(r["detection_id"])
                    for r in display_rows
                }
                selected_treat_labels = st.multiselect(
                    "Simulate Residual Risk Treatment (-2 Exposure)",
                    options=list(treat_options.keys()),
                    default=[k for k, v in treat_options.items() if v in treated_ids],
                )
                new_treated_set = {treat_options[lbl] for lbl in selected_treat_labels}
                if new_treated_set != treated_ids:
                    st.session_state["treated_ids"] = new_treated_set
                    st.rerun()
            with q_col2:
                if display_rows:
                    pick_map = {
                        f"S{r['detection_id']} • {r['host']} — {r['title']} (L={r['likelihood']}, I={r['impact']})": r
                        for r in display_rows
                    }
                    picked_lbl = st.selectbox("Select Scenario to Edit or Delete", list(pick_map.keys()))
                    picked_r = pick_map[picked_lbl]
                    p_id = int(picked_r["detection_id"])
                    qe_1, qe_2, qe_3, qe_4 = st.columns(4)
                    with qe_1:
                        ql = st.number_input("L (1-5)", 1, 5, int(picked_r["likelihood"]), key=f"ql_{p_id}")
                    with qe_2:
                        qi = st.number_input("I (1-5)", 1, 5, int(picked_r["impact"]), key=f"qi_{p_id}")
                    with qe_3:
                        if st.button("💾 Update L×I", key=f"qupd_{p_id}", use_container_width=True, type="primary"):
                            conn = get_connection()
                            try:
                                update_risk_in_db(conn, detection_id=p_id, likelihood=int(ql), impact=int(qi))
                            finally:
                                conn.close()
                            st.rerun()
                    with qe_4:
                        if st.button("🗑️ Delete", key=f"qdel_{p_id}", use_container_width=True):
                            conn = get_connection()
                            try:
                                delete_risk_from_db(conn, detection_id=p_id)
                            finally:
                                conn.close()
                            st.rerun()

    # =================================================================
    # RIGHT COLUMN: 5x5 RISK MATRIX (Exact Screenshot HTML Grid)
    # =================================================================
    with col_right:
        coord_labels: dict[tuple[int, int], list[str]] = {}
        for r in display_rows:
            coord = (int(r["active_l"]), int(r["impact"]))
            coord_labels.setdefault(coord, []).append(f"S{r['detection_id']}")

        active_cell = st.session_state["hm_cell_filter"]

        matrix_rows_html = []
        for l_val in range(5, 0, -1):
            cells_html = []
            for i_val in range(1, 6):
                score_val = l_val * i_val
                scen_list = coord_labels.get((l_val, i_val), [])
                has_cls = "has-scen" if scen_list else ""
                act_cls = "active-cell" if active_cell == (l_val, i_val) else ""

                if score_val >= 20:
                    band_cls = "cell-crit"
                    tag_cls = "soc-matrix-tag crit-tag"
                elif score_val >= 12:
                    band_cls = "cell-high"
                    tag_cls = "soc-matrix-tag"
                elif score_val >= 6:
                    band_cls = "cell-med"
                    tag_cls = "soc-matrix-tag"
                else:
                    band_cls = "cell-low"
                    tag_cls = "soc-matrix-tag"

                tag_html = f'<div class="{tag_cls}">{", ".join(scen_list)}</div>' if scen_list else ""
                cells_html.append(
                    f'<div class="soc-matrix-cell {band_cls} {has_cls} {act_cls}">'
                    f"<div>{score_val}</div>"
                    f"{tag_html}"
                    f"</div>"
                )
            matrix_rows_html.append(f'<div class="soc-matrix-row">{"".join(cells_html)}</div>')

        crit_scen_tags = ", ".join(f"S{r['detection_id']}" for r in display_rows if r["active_band"] == "Critical") or "None"

        st.markdown(
            f"""
            <div class="soc-panel">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.85rem;">
                    <div style="display:flex; align-items:center; gap:0.45rem;">
                        <span style="color:#adc6ff; font-family:'JetBrains Mono',monospace; font-weight:700;">#</span>
                        <span style="font-size:1.08rem; font-weight:700; color:#dce2f7;">5x5 Risk Matrix</span>
                    </div>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; color:#8c909f; text-transform:uppercase; letter-spacing:0.05em;">Click Cell Below To Highlight</span>
                </div>
                <div class="soc-matrix-wrap">
                    <div class="soc-matrix-ylabel">LIKELIHOOD (1 - 5)</div>
                    <div>
                        {''.join(matrix_rows_html)}
                        <div style="display:grid; grid-template-columns:repeat(5, 1fr); gap:0.35rem; text-align:center; font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#8c909f; margin-top:0.3rem;">
                            <div>I:1</div><div>I:2</div><div>I:3</div><div>I:4</div><div>I:5</div>
                        </div>
                        <div style="text-align:center; font-family:'JetBrains Mono',monospace; font-size:0.62rem; font-weight:700; color:#8c909f; letter-spacing:0.06em; margin-top:0.35rem;">
                            IMPACT: ASSET SENSITIVITY (1 - 5)
                        </div>
                    </div>
                </div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.45rem; font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#c2c6d6; margin-top:0.95rem; margin-bottom:0.8rem; padding-top:0.75rem; border-top:1px solid #232a3a;">
                    <div><span style="display:inline-block;width:10px;height:10px;background:#182032;border:1px solid #8c909f;border-radius:2px;margin-right:6px;"></span>Low (1-5)</div>
                    <div><span style="display:inline-block;width:10px;height:10px;background:#1c3338;border:1px solid #4edea3;border-radius:2px;margin-right:6px;"></span>Med (6-11)</div>
                    <div><span style="display:inline-block;width:10px;height:10px;background:#2d3070;border:1px solid #c0c1ff;border-radius:2px;margin-right:6px;"></span>High (12-19)</div>
                    <div><span style="display:inline-block;width:10px;height:10px;background:#ffb4ab;border:1px solid #ffb4ab;border-radius:2px;margin-right:6px;"></span>Critical (20-25)</div>
                </div>
                <div style="background:#070e1d; border:1px solid #232a3a; padding:0.7rem 0.8rem; border-radius:0.45rem; font-size:0.76rem; color:#c2c6d6;">
                    <div style="display:flex; justify-content:space-between; font-family:'JetBrains Mono',monospace; font-size:0.68rem; margin-bottom:0.25rem;">
                        <span style="color:#8c909f;">Cluster Density</span>
                        <span style="color:#4edea3; font-weight:700;">Concentrated (Q2)</span>
                    </div>
                    Critical assets (<code style="color:#ffb4ab;">{crit_scen_tags}</code>) gravitate towards Top-Right quadrant due to maximum institutional asset weights (<code style="color:#adc6ff;">I=5</code>).
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Interactive Cell Selector to highlight & filter
        populated_coords = sorted(coord_labels.keys(), key=lambda c: -(c[0] * c[1]))
        cell_opts = ["All Matrix Cells (No Filter)"] + [
            f"Cell L={l_v} × I={i_v} (Score {l_v*i_v}: {', '.join(coord_labels[(l_v, i_v)])})"
            for (l_v, i_v) in populated_coords
        ]
        curr_c_idx = (
            populated_coords.index(active_cell) + 1
            if active_cell in populated_coords
            else 0
        )
        picked_cell = st.selectbox(
            "Highlight & Filter by Matrix Cell",
            options=cell_opts,
            index=curr_c_idx,
            label_visibility="collapsed",
        )
        if picked_cell == "All Matrix Cells (No Filter)":
            if st.session_state["hm_cell_filter"] is not None:
                st.session_state["hm_cell_filter"] = None
                st.rerun()
        else:
            sel_coord = populated_coords[cell_opts.index(picked_cell) - 1]
            if st.session_state["hm_cell_filter"] != sel_coord:
                st.session_state["hm_cell_filter"] = sel_coord
                st.rerun()

    # --- Bottom Section: Live Ingestion Summary & Quick Control Failures (Exact Screenshot Cards + Action Buttons) ---
    st.markdown(
        """
        <div class="soc-panel">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.9rem; flex-wrap:wrap; gap:0.75rem;">
                <div style="display:flex; align-items:center; gap:0.6rem;">
                    <span style="font-size:1.2rem; color:#ffb4ab;">⚠️</span>
                    <div>
                        <div style="font-size:1.08rem; font-weight:700; color:#dce2f7;">Live Ingestion Summary & Quick Control Failures</div>
                        <div style="font-size:0.78rem; color:#8c909f;">NIST SP 800-53 security control deviations parsed from syslog event streams</div>
                    </div>
                </div>
            </div>
            <div class="alert-grid-3">
                <div class="soc-alert-card">
                    <div style="display:flex; justify-content:space-between; margin-bottom:0.4rem;">
                        <span style="background:#93000a; color:#ffdad6; font-family:'JetBrains Mono',monospace; font-size:0.62rem; font-weight:700; padding:2px 7px; border-radius:3px;">AC-7 FAILED</span>
                        <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:#8c909f;">pay-srv-01</span>
                    </div>
                    <div style="font-weight:700; font-size:0.9rem; color:#dce2f7; margin-bottom:0.3rem;">Unenforced Lockout Policy</div>
                    <div style="font-size:0.76rem; color:#c2c6d6; margin-bottom:0.55rem; line-height:1.4;">
                        No account lockout detected after 12 consecutive failed SSH attempts against <code style="color:#adc6ff;">payroll-admin</code> on <code style="color:#adc6ff;">pay-srv-01</code>.
                    </div>
                    <div style="display:flex; justify-content:space-between; font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#8c909f;">
                        <span>Threat: T1110.001</span>
                        <span style="color:#ffb4ab; font-weight:700;">Severity: 4</span>
                    </div>
                </div>
                <div class="soc-alert-card">
                    <div style="display:flex; justify-content:space-between; margin-bottom:0.4rem;">
                        <span style="background:#93000a; color:#ffdad6; font-family:'JetBrains Mono',monospace; font-size:0.62rem; font-weight:700; padding:2px 7px; border-radius:3px;">AC-6 FAILED</span>
                        <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:#8c909f;">db-srv-01</span>
                    </div>
                    <div style="font-weight:700; font-size:0.9rem; color:#dce2f7; margin-bottom:0.3rem;">Least Privilege Breach</div>
                    <div style="font-size:0.76rem; color:#c2c6d6; margin-bottom:0.55rem; line-height:1.4;">
                        Unauthorized sudo elevation to <code style="color:#ffb4ab;">root</code> executed by user <code style="color:#adc6ff;">'bob'</code> inside academic database.
                    </div>
                    <div style="display:flex; justify-content:space-between; font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#8c909f;">
                        <span>Threat: T1548.003</span>
                        <span style="color:#ffb4ab; font-weight:700;">Severity: 5</span>
                    </div>
                </div>
                <div class="soc-alert-card secondary-border">
                    <div style="display:flex; justify-content:space-between; margin-bottom:0.4rem;">
                        <span style="background:#3131c0; color:#e1e0ff; font-family:'JetBrains Mono',monospace; font-size:0.62rem; font-weight:700; padding:2px 7px; border-radius:3px;">SC-7 FAILED</span>
                        <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:#8c909f;">exam-srv-01</span>
                    </div>
                    <div style="font-weight:700; font-size:0.9rem; color:#dce2f7; margin-bottom:0.3rem;">Boundary Protection Ingress</div>
                    <div style="font-size:0.76rem; color:#c2c6d6; margin-bottom:0.55rem; line-height:1.4;">
                        15 rapid port scans detected against examination server ports 8080/443 within a 28-second sampling window.
                    </div>
                    <div style="display:flex; justify-content:space-between; font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#8c909f;">
                        <span>Threat: T1046</span>
                        <span style="color:#c0c1ff; font-weight:700;">Severity: 3</span>
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    bot_c1, bot_c2, bot_c3, _ = st.columns([2, 2, 2.5, 5.5])
    with bot_c1:
        q_csv = io.StringIO()
        pd.DataFrame(display_rows).to_csv(q_csv, index=False)
        st.download_button(
            "📥 Export CSV",
            data=q_csv.getvalue(),
            file_name="risk_ranked_queue.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with bot_c2:
        if st.button("✳️ Run Tamper Test", use_container_width=True):
            try:
                tamper_record(record_id=150)
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    with bot_c3:
        if st.button("🛡️ View Full Audit Evidence", type="primary", use_container_width=True):
            st.session_state["selected_page"] = "3. Audit Evidence & Issues"
            st.rerun()


# =====================================================================
# PAGE 2: METHODOLOGY & CATALOGS (DARK SOC THEME + INTERACTIVE EDITORS)
# =====================================================================
elif selected_page == "2. Methodology & Catalogs":
    assets_list = state["assets"]
    threats_map = load_threats_csv()
    vulns_map = load_vulnerabilities_csv()
    tv_pairs = load_tv_pairs_csv()

    st.markdown(
        f"""
        <div class="soc-banner">
            <div>
                <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.35rem;">
                    <span class="soc-badge-green">SOC STAGE: ASSET & CATALOG ARCHITECTURE</span>
                    <span style="color:#8c909f;">•</span>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:#c2c6d6;">Unit 2 & Unit 3 Reference Core</span>
                </div>
                <div style="font-size:1.55rem; font-weight:700; color:#dce2f7;">Risk Scoring Methodology & Interactive Reference Catalogs</div>
                <div style="font-size:0.84rem; color:#c2c6d6;">Greenfield Institute of Technology (GIT) — Edit Asset Inventory & Exposure Matrix interactively to dynamically recompute scores</div>
            </div>
        </div>
        <div class="soc-kpi-grid">
            <div class="soc-kpi-card" style="border-bottom: 3px solid #4d8eff;">
                <div class="soc-kpi-title"><span>SCOPED ASSETS</span><span>🖥️</span></div>
                <div class="soc-kpi-value" style="color:#adc6ff;">{len(assets_list)}</div>
                <div class="soc-kpi-sub"><span>CIA & Value Rated (1–5)</span><span class="soc-badge-green">ACTIVE</span></div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #ffb4ab;">
                <div class="soc-kpi-title" style="color:#ffb4ab;"><span>MITRE ATT&CK THREATS</span><span>🎯</span></div>
                <div class="soc-kpi-value" style="color:#ffb4ab;">{len(threats_map)}</div>
                <div class="soc-kpi-sub"><span>T1110, T1046, T1548</span><span class="band-pill band-critical">MAPPED</span></div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #c0c1ff;">
                <div class="soc-kpi-title"><span>VULNERABILITY CATALOG</span><span>🔓</span></div>
                <div class="soc-kpi-value" style="color:#dce2f7;">{len(vulns_map)}V / {len(tv_pairs)}TV</div>
                <div class="soc-kpi-sub"><span>Threat-Vuln Pairs Linked</span><span class="band-pill band-high">VERIFIED</span></div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #4edea3;">
                <div class="soc-kpi-title" style="color:#4edea3;"><span>SCORING MODEL</span><span>🧮</span></div>
                <div class="soc-kpi-value" style="color:#4edea3; font-size:1.4rem;">R = L × I</div>
                <div class="soc-kpi-sub"><span>round_half_up(x)</span><span class="soc-badge-green">DETERMINISTIC</span></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns(2, gap="medium")
    with c1:
        st.markdown(
            """
            <div class="soc-panel">
                <div class="soc-panel-header">
                    <span style="font-size:1rem; font-weight:700; color:#dce2f7;">2.1 Interactive Asset Inventory (assets table)</span>
                    <span class="soc-badge-green">EDITABLE CRUD</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        assets_df = pd.DataFrame(assets_list)
        edited_assets_df = st.data_editor(
            assets_df,
            num_rows="dynamic",
            use_container_width=True,
            hide_index=True,
            key="assets_editor_soc",
        )
        if st.button("💾 Save Asset Inventory & Recompute Risk Scores", type="primary", use_container_width=True):
            conn = get_connection()
            try:
                old_ids = {r["asset_id"] for r in assets_list}
                new_ids = set()
                for _, row in edited_assets_df.iterrows():
                    aid = str(row.get("asset_id") or "").strip()
                    if not aid:
                        continue
                    new_ids.add(aid)
                    upsert_asset_in_db(
                        conn,
                        asset_id=aid,
                        hostname=str(row.get("hostname") or f"{aid.lower()}-srv"),
                        name=str(row.get("name") or aid),
                        asset_type=str(row.get("type") or "server"),
                        owner=str(row.get("owner") or "IT Security"),
                        value=int(row.get("value") or 3),
                        c=int(row.get("c") or 3),
                        i=int(row.get("i") or 3),
                        a=int(row.get("a") or 3),
                    )
                for rem_id in old_ids - new_ids:
                    delete_asset_from_db(conn, rem_id)
                recalculate_scores_from_assets_and_exposure(conn, exposure_override=st.session_state["custom_exposure"])
            finally:
                conn.close()
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown(
            """
            <div class="soc-panel">
                <div class="soc-panel-header">
                    <span style="font-size:1rem; font-weight:700; color:#dce2f7;">2.2 Threat Catalog (data/threats.csv)</span>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#adc6ff;">MITRE ATT&CK</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        st.dataframe(pd.read_csv(DATA_DIR / "threats.csv"), use_container_width=True, hide_index=True)
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown(
            """
            <div class="soc-panel">
                <div class="soc-panel-header">
                    <span style="font-size:1rem; font-weight:700; color:#dce2f7;">2.3 Vulnerability Catalog (data/vulnerabilities.csv)</span>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#adc6ff;">V1–V4</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        st.dataframe(pd.read_csv(DATA_DIR / "vulnerabilities.csv"), use_container_width=True, hide_index=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with c2:
        st.markdown(
            """
            <div class="soc-panel">
                <div class="soc-panel-header">
                    <span style="font-size:1rem; font-weight:700; color:#dce2f7;">2.4 Interactive Vulnerability Exposure Matrix (1–5)</span>
                    <span class="soc-badge-green">EDITABLE CRUD</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        exp_rows = [{"asset_id": aid, **tmap} for aid, tmap in st.session_state["custom_exposure"].items()]
        edited_exp_df = st.data_editor(
            pd.DataFrame(exp_rows),
            num_rows="dynamic",
            use_container_width=True,
            hide_index=True,
            key="exp_editor_soc",
        )
        if st.button("🔄 Apply Exposure Matrix & Recompute Risk Scores", type="primary", use_container_width=True):
            updated_exp: dict[str, dict[str, int]] = {}
            for _, row in edited_exp_df.iterrows():
                aid = str(row.get("asset_id") or "").strip()
                if not aid:
                    continue
                updated_exp[aid] = {
                    "T1110": clamp(int(row.get("T1110") or 3), 1, 5),
                    "T1046": clamp(int(row.get("T1046") or 3), 1, 5),
                    "T1548": clamp(int(row.get("T1548") or 3), 1, 5),
                }
            st.session_state["custom_exposure"] = updated_exp
            conn = get_connection()
            try:
                recalculate_scores_from_assets_and_exposure(conn, exposure_override=updated_exp)
            finally:
                conn.close()
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown(
            """
            <div class="soc-panel">
                <div class="soc-panel-header">
                    <span style="font-size:1rem; font-weight:700; color:#dce2f7;">2.5 Threat–Vulnerability Pairs & Control Mapping</span>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#adc6ff;">NIST 800-53 / CIS v8</span>
                </div>
            """,
            unsafe_allow_html=True,
        )
        tv_enriched = [
            {
                "threat_id": p["threat_id"],
                "threat_name": threats_map[p["threat_id"]]["name"],
                "vuln_id": p["vuln_id"],
                "vuln_name": vulns_map[p["vuln_id"]]["name"],
            }
            for p in tv_pairs
        ]
        st.dataframe(pd.DataFrame(tv_enriched), use_container_width=True, hide_index=True)
        st.dataframe(pd.read_csv(DATA_DIR / "control_map.csv"), use_container_width=True, hide_index=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(
        """
        <div class="soc-panel">
            <div class="soc-panel-header">
                <span style="font-size:1rem; font-weight:700; color:#dce2f7;">2.6 Mathematical Risk Scoring Specification & Worked Example</span>
                <span class="soc-badge-green">ALGORITHM: GIT-RiskMatrix-v3</span>
            </div>
        """,
        unsafe_allow_html=True,
    )
    st.markdown(
        r"""
        Using deterministic rounding helper $\text{round\_half\_up}(x) = \lfloor x + 0.5 \rfloor$:

        1. **Impact ($I$):** $I = \text{clamp}\left(\text{round\_half\_up}\left(\frac{A.\text{value} + A.\text{rating}[T.\text{primary\_dimension}]}{2}\right), 1, 5\right)$
        2. **Frequency Bonus ($F$):** T1110 ($n < 20 \Rightarrow 0$, $20\text{–}39 \Rightarrow 0.5$, $n \ge 40 \Rightarrow 1.0$); T1046 ($n < 25 \Rightarrow 0$, $25\text{–}49 \Rightarrow 0.5$, $n \ge 50 \Rightarrow 1.0$); T1548 ($0.0$).
        3. **Likelihood ($L$):** $L = \min\left(5, \max\left(1, \text{round\_half\_up}\left(\frac{T.\text{base\_likelihood} + \text{exposure}[A][T]}{2} + F\right)\right)\right)$
        4. **Risk Score ($R$):** $R = L \times I$ (range $1\text{–}25$), mapped to **Critical (20–25)**, **High (12–19)**, **Medium (6–11)**, **Low (1–5)**.
        """
    )
    st.markdown("</div>", unsafe_allow_html=True)


# =====================================================================
# PAGE 3: AUDIT EVIDENCE & ISSUES REGISTER (DARK SOC THEME + CRUD)
# =====================================================================
elif selected_page == "3. Audit Evidence & Issues":
    evidence = state["evidence"]
    issues = state["issues"]

    direct_count = sum(1 for e in evidence if e["type"] == "direct")
    indirect_count = sum(1 for e in evidence if e["type"] == "indirect")
    open_cnt = sum(1 for i in issues if i["status"] == "Open")
    treated_cnt = sum(1 for i in issues if i["status"] in ("In treatment", "Implemented", "Verified"))

    st.markdown(
        f"""
        <div class="soc-banner">
            <div>
                <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.35rem;">
                    <span class="soc-badge-green">SOC STAGE: COMPLIANCE & EVIDENCE TRIAGE</span>
                    <span style="color:#8c909f;">•</span>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:#c2c6d6;">Unit 4 & Unit 5 Audit Layer</span>
                </div>
                <div style="font-size:1.55rem; font-weight:700; color:#dce2f7;">Audit Evidence Explorer & Interactive Issues Register</div>
                <div style="font-size:0.84rem; color:#c2c6d6;">Direct log evidence linked to SHA-256 chain hashes, indirect correlation records, and interactive NIST SP 800-53 / CIS v8 Issues Register</div>
            </div>
        </div>
        <div class="soc-kpi-grid">
            <div class="soc-kpi-card" style="border-bottom: 3px solid #4d8eff;">
                <div class="soc-kpi-title"><span>DIRECT EVIDENCE</span><span>📄</span></div>
                <div class="soc-kpi-value" style="color:#adc6ff;">{direct_count}</div>
                <div class="soc-kpi-sub"><span>Raw Syslog Lines Linked</span><span class="soc-badge-green">SHA-256 LINKED</span></div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #4edea3;">
                <div class="soc-kpi-title" style="color:#4edea3;"><span>INDIRECT EVIDENCE</span><span>🔗</span></div>
                <div class="soc-kpi-value" style="color:#4edea3;">{indirect_count}</div>
                <div class="soc-kpi-sub"><span>Correlation & Score Records</span><span class="soc-badge-green">DERIVED</span></div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #ffb4ab;">
                <div class="soc-kpi-title" style="color:#ffb4ab;"><span>OPEN CONTROL ISSUES</span><span>⚠️</span></div>
                <div class="soc-kpi-value" style="color:#ffb4ab;">{open_cnt}</div>
                <div class="soc-kpi-sub"><span>Failed AC-7, SC-7, AC-6</span><span class="band-pill band-critical">ACTION REQ</span></div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #c0c1ff;">
                <div class="soc-kpi-title"><span>IN TREATMENT / VERIFIED</span><span>🛡️</span></div>
                <div class="soc-kpi-value" style="color:#dce2f7;">{treated_cnt}</div>
                <div class="soc-kpi-sub"><span>Total Tracked: {len(issues)}</span><span class="band-pill band-high">REMEDIATION</span></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="soc-panel">
            <div class="soc-panel-header">
                <div style="display:flex; align-items:center; gap:0.55rem;">
                    <span style="color:#ffb4ab; font-weight:700;">☰</span>
                    <span style="font-size:1.05rem; font-weight:700; color:#dce2f7;">3.1 Interactive Issues & Control Failures Register (issues table)</span>
                </div>
                <span class="soc-badge-green">INLINE STATUS & TREATMENT CRUD</span>
            </div>
        """,
        unsafe_allow_html=True,
    )

    if not issues:
        st.success("0 open issues in the Issues Register (all evaluated security controls passed!).")
    else:
        issues_df = pd.DataFrame(issues)
        edited_issues_df = st.data_editor(
            issues_df,
            num_rows="dynamic",
            use_container_width=True,
            hide_index=True,
            key="soc_issues_editor",
            disabled=["issue_id", "detection_id", "risk_band", "created_at"],
            column_config={
                "status": st.column_config.SelectboxColumn(
                    "Status",
                    options=["Open", "In treatment", "Implemented", "Verified"],
                    required=True,
                ),
                "risk_score": st.column_config.NumberColumn("Risk Score", min_value=1, max_value=25, step=1),
            },
        )
        ic_1, ic_2, _ = st.columns([2.5, 2.5, 5])
        with ic_1:
            if st.button("💾 Save Issues Register Changes", type="primary", use_container_width=True):
                conn = get_connection()
                try:
                    existing_ids = {int(i["issue_id"]) for i in issues}
                    kept_ids = set()
                    for _, row in edited_issues_df.iterrows():
                        raw_id = row.get("issue_id")
                        if pd.notna(raw_id) and int(raw_id) in existing_ids:
                            iid = int(raw_id)
                            kept_ids.add(iid)
                            update_issue_in_db(
                                conn,
                                issue_id=iid,
                                title=str(row.get("title") or ""),
                                owner=str(row.get("owner") or "IT Security"),
                                recommended_treatment=str(row.get("recommended_treatment") or ""),
                                status=str(row.get("status") or "Open"),
                                risk_score=int(row.get("risk_score") or 10),
                            )
                    for del_iid in existing_ids - kept_ids:
                        delete_issue_from_db(conn, del_iid)
                finally:
                    conn.close()
                st.rerun()
        with ic_2:
            issues_csv_buf = io.StringIO()
            pd.DataFrame(issues).to_csv(issues_csv_buf, index=False)
            st.download_button(
                label="📥 Download Issues (issues.csv)",
                data=issues_csv_buf.getvalue(),
                file_name="issues.csv",
                mime="text/csv",
                use_container_width=True,
            )

    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(
        """
        <div class="soc-panel">
            <div class="soc-panel-header">
                <div style="display:flex; align-items:center; gap:0.55rem;">
                    <span style="color:#adc6ff; font-weight:700;">🔍</span>
                    <span style="font-size:1.05rem; font-weight:700; color:#dce2f7;">3.2 Audit Evidence Explorer (Direct & Indirect Evidence)</span>
                </div>
                <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:#4edea3;">NIST AU-9 / CIS Control 8</span>
            </div>
        """,
        unsafe_allow_html=True,
    )

    f1, f2, f3 = st.columns(3)
    with f1:
        ev_type_filter = st.selectbox("Evidence Type", ["All", "direct", "indirect"])
    with f2:
        hosts_avail = ["All"] + sorted({e["source_host"] for e in evidence})
        ev_host_filter = st.selectbox("Source Host", hosts_avail)
    with f3:
        ctrls_avail = ["All"] + sorted({e["control_nist"] for e in evidence})
        ev_ctrl_filter = st.selectbox("NIST 800-53 Control", ctrls_avail)

    filtered_ev = [
        e
        for e in evidence
        if (ev_type_filter == "All" or e["type"] == ev_type_filter)
        and (ev_host_filter == "All" or e["source_host"] == ev_host_filter)
        and (ev_ctrl_filter == "All" or e["control_nist"] == ev_ctrl_filter)
    ]

    st.dataframe(pd.DataFrame(filtered_ev), use_container_width=True, hide_index=True, height=340)

    ev_csv_buf = io.StringIO()
    pd.DataFrame(evidence).to_csv(ev_csv_buf, index=False)
    st.download_button(
        label="📥 Download Full Evidence Table (evidence.csv)",
        data=ev_csv_buf.getvalue(),
        file_name="evidence.csv",
        mime="text/csv",
    )
    st.markdown("</div>", unsafe_allow_html=True)


# =====================================================================
# PAGE 4: TAMPER-EVIDENT LOG CHAIN (DARK SOC THEME)
# =====================================================================
elif selected_page == "4. Tamper-Evident Log Chain":
    conn = get_connection()
    try:
        live_verify = verify_chain(conn)
    finally:
        conn.close()

    anchor_obj = live_verify.get("anchor") or {}
    c_ok = live_verify["ok"]
    c_col = "#4edea3" if c_ok else "#ffb4ab"
    c_txt = "INTACT (VALID)" if c_ok else f"TAMPERED (ID #{live_verify['first_broken_id']})"

    st.markdown(
        f"""
        <div class="soc-banner">
            <div>
                <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.35rem;">
                    <span class="soc-badge-green">SOC STAGE: CRYPTOGRAPHIC LOG INTEGRITY</span>
                    <span style="color:#8c909f;">•</span>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:#c2c6d6;">NIST AU-9 / CIS Control 8</span>
                </div>
                <div style="font-size:1.55rem; font-weight:700; color:#dce2f7;">Tamper-Evident SHA-256 Log Chain & External Anchor</div>
                <div style="font-size:0.84rem; color:#c2c6d6;">Cryptographic hash chaining across every ingested log event with external anchor verification (anchor/head.txt)</div>
            </div>
        </div>
        <div class="soc-kpi-grid">
            <div class="soc-kpi-card" style="border-bottom: 3px solid {c_col};">
                <div class="soc-kpi-title" style="color:{c_col};"><span>CHAIN VERIFICATION</span><span>🛡️</span></div>
                <div class="soc-kpi-value" style="color:{c_col}; font-size:1.45rem;">{c_txt}</div>
                <div class="soc-kpi-sub"><span>Status: {live_verify['reason']}</span><span class="soc-badge-green">{'PASS' if c_ok else 'FAIL'}</span></div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #4d8eff;">
                <div class="soc-kpi-title"><span>BLOCKS VERIFIED</span><span>⛓️</span></div>
                <div class="soc-kpi-value" style="color:#adc6ff;">{live_verify['checked']}</div>
                <div class="soc-kpi-sub"><span>Anchored Count: {anchor_obj.get('row_count', 0)}</span><span class="soc-badge-green">SHA-256</span></div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #c0c1ff;">
                <div class="soc-kpi-title"><span>RECOMPUTED HEAD</span><span>#️⃣</span></div>
                <div class="soc-kpi-value" style="color:#dce2f7; font-size:1.15rem; font-family:'JetBrains Mono',monospace;">{live_verify['head_hash'][:14]}...</div>
                <div class="soc-kpi-sub"><span>Genesis: 00000000...</span><span class="band-pill band-high">HEAD</span></div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #4edea3;">
                <div class="soc-kpi-title" style="color:#4edea3;"><span>EXTERNAL ANCHOR</span><span>⚓</span></div>
                <div class="soc-kpi-value" style="color:#4edea3; font-size:1.15rem; font-family:'JetBrains Mono',monospace;">{str(anchor_obj.get('head_hash', ''))[:14]}...</div>
                <div class="soc-kpi-sub"><span>anchor/head.txt</span><span class="soc-badge-green">WORM SIM</span></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    btn_c1, btn_c2, btn_c3 = st.columns([2, 2, 2])
    with btn_c1:
        st.button("🔍 Verify Integrity Now", use_container_width=True, type="primary")
    with btn_c2:
        if st.button("💥 Simulate Tamper on Record #150", use_container_width=True):
            try:
                tamper_record(record_id=150)
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    with btn_c3:
        if st.button("♻️ Reset & Restore Clean Chain", use_container_width=True):
            reset_environment(verbose=False)
            st.rerun()

    if live_verify["ok"]:
        st.markdown(
            f"""
            <div style="background:rgba(78,222,163,0.12); border:2px solid #4edea3; border-radius:0.75rem; padding:1.2rem 1.5rem; margin:0.75rem 0;">
                <div style="font-size:1.25rem; font-weight:700; color:#4edea3; margin-bottom:0.35rem;">
                    ✅ CHAIN INTACT — ALL {live_verify['checked']} LOG BLOCKS VERIFIED
                </div>
                <div style="font-family:'JetBrains Mono',monospace; font-size:0.8rem; color:#dce2f7;">
                    Recomputed Head Hash matches external anchor (<code>anchor/head.txt</code>). Zero modifications, deletions, or reorderings detected.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div style="background:rgba(147,0,10,0.35); border:2px solid #ffb4ab; border-radius:0.75rem; padding:1.2rem 1.5rem; margin:0.75rem 0;">
                <div style="font-size:1.25rem; font-weight:700; color:#ffb4ab; margin-bottom:0.35rem;">
                    🚨 TAMPERING DETECTED AT RECORD ID {live_verify['first_broken_id']}
                </div>
                <div style="font-family:'JetBrains Mono',monospace; font-size:0.82rem; color:#ffdad6;">
                    Reason: <strong>{live_verify['reason']}</strong> (Checked {live_verify['checked']} blocks before failure)
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    c_left, c_right = st.columns(2)
    with c_left:
        st.markdown(
            """
            <div class="soc-panel">
                <div class="soc-panel-header"><span style="font-weight:700; color:#dce2f7;">Cryptographic Chain State</span></div>
            """,
            unsafe_allow_html=True,
        )
        st.code(
            f"Genesis Hash    : {'0' * 64}\n"
            f"Recomputed Head : {live_verify['head_hash']}\n"
            f"Records Checked : {live_verify['checked']}\n"
            f"Status          : {live_verify['reason']}",
            language="text",
        )
        st.markdown("</div>", unsafe_allow_html=True)
    with c_right:
        st.markdown(
            """
            <div class="soc-panel">
                <div class="soc-panel-header"><span style="font-weight:700; color:#dce2f7;">External Anchor (anchor/head.txt)</span></div>
            """,
            unsafe_allow_html=True,
        )
        st.code(json.dumps(anchor_obj, indent=2), language="json")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(
        """
        <div class="soc-panel">
            <div class="soc-panel-header">
                <span style="font-weight:700; color:#dce2f7;">Stored Log Chain (log_events table)</span>
                <span class="soc-badge-green">SHA-256 BLOCKS</span>
            </div>
        """,
        unsafe_allow_html=True,
    )
    logs_df = pd.DataFrame(state["logs"])
    if not live_verify["ok"] and live_verify["first_broken_id"] is not None:
        broken_id = int(live_verify["first_broken_id"])
        broken_rows = logs_df[logs_df["id"] == broken_id]
        if not broken_rows.empty:
            st.warning(f"Inspecting tampered record `id = {broken_id}`:")
            st.dataframe(broken_rows, use_container_width=True, hide_index=True)

    st.dataframe(logs_df, use_container_width=True, hide_index=True, height=320)
    st.markdown("</div>", unsafe_allow_html=True)


# =====================================================================
# PAGE 5: BASELINE VS. RISK VALIDATION (DARK SOC THEME)
# =====================================================================
elif selected_page == "5. Baseline vs Validation":
    detections = sorted(state["detections"], key=lambda x: int(x["detection_id"]))

    up_shifts = sum(1 for d in detections if (int(d["baseline_rank"]) - int(d["risk_rank"])) > 0)
    down_shifts = sum(1 for d in detections if (int(d["baseline_rank"]) - int(d["risk_rank"])) < 0)

    st.markdown(
        f"""
        <div class="soc-banner">
            <div>
                <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.35rem;">
                    <span class="soc-badge-green">SOC STAGE: VALIDATION & BENCHMARK</span>
                    <span style="color:#8c909f;">•</span>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:#c2c6d6;">Section 11 Reproduction & Live Shifts</span>
                </div>
                <div style="font-size:1.55rem; font-weight:700; color:#dce2f7;">Baseline (Plain-Severity) vs. Contextual Risk Ranking Validation</div>
                <div style="font-size:0.84rem; color:#c2c6d6;">Side-by-side comparison demonstrating how business asset criticality and exposure shift alert triage priority</div>
            </div>
        </div>
        <div class="soc-kpi-grid">
            <div class="soc-kpi-card" style="border-bottom: 3px solid #4d8eff;">
                <div class="soc-kpi-title"><span>EVALUATED SCENARIOS</span><span>📊</span></div>
                <div class="soc-kpi-value" style="color:#adc6ff;">{len(detections)}</div>
                <div class="soc-kpi-sub"><span>Live Register Scenarios</span><span class="soc-badge-green">RANKED</span></div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #4edea3;">
                <div class="soc-kpi-title" style="color:#4edea3;"><span>PROMOTED IN PRIORITY</span><span>▲</span></div>
                <div class="soc-kpi-value" style="color:#4edea3;">{up_shifts}</div>
                <div class="soc-kpi-sub"><span>Positive Rank Shift (+Shift)</span><span class="soc-badge-green">ELEVATED</span></div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #ffb4ab;">
                <div class="soc-kpi-title" style="color:#ffb4ab;"><span>DE-PRIORITIZED NOISE</span><span>▼</span></div>
                <div class="soc-kpi-value" style="color:#ffb4ab;">{down_shifts}</div>
                <div class="soc-kpi-sub"><span>Low-Impact High-Volume</span><span class="band-pill band-critical">SUPPRESSED</span></div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 3px solid #c0c1ff;">
                <div class="soc-kpi-title"><span>KEY SHIFT (S4 VS S3)</span><span>⚡</span></div>
                <div class="soc-kpi-value" style="color:#dce2f7; font-size:1.45rem;">+2 vs -2</div>
                <div class="soc-kpi-sub"><span>pay-srv-01 Outranks gw-01</span><span class="band-pill band-high">PROVEN</span></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not detections:
        st.info("No risk scenarios in register. Click 'Re-verify & Reset' in the sidebar.")
    else:
        val_rows = []
        table_html = []
        for d in detections:
            shift = int(d["baseline_rank"]) - int(d["risk_rank"])
            arrow = f"▲ +{shift}" if shift > 0 else (f"▼ {shift}" if shift < 0 else "● 0")
            s_col = "#4edea3" if shift > 0 else ("#ffb4ab" if shift < 0 else "#8c909f")
            val_rows.append(
                {
                    "Scenario": f"S{d['detection_id']}",
                    "Asset": f"{d['asset_id']} {d['host']}",
                    "Asset Name": d["asset_name"],
                    "Threat": d["threat_id"],
                    "n": int(d["event_count"]),
                    "Severity": int(d["severity"]),
                    "L": int(d["likelihood"]),
                    "I": int(d["impact"]),
                    "Risk": int(d["risk"]),
                    "Band": d["band"],
                    "Baseline rank": int(d["baseline_rank"]),
                    "Risk rank": int(d["risk_rank"]),
                    "Shift": shift,
                    "Rank Shift": arrow,
                }
            )
            table_html.append(
                f"<tr>"
                f'<td style="font-family:\'JetBrains Mono\',monospace; font-weight:700; color:#adc6ff;">S{d["detection_id"]}</td>'
                f'<td style="font-family:\'JetBrains Mono\',monospace;">{d["asset_id"]} • {d["host"]} <span style="color:#8c909f;">({d["asset_name"]})</span></td>'
                f'<td style="font-family:\'JetBrains Mono\',monospace; color:#c0c1ff;">{d["threat_id"]}</td>'
                f'<td style="text-align:right; font-family:\'JetBrains Mono\',monospace;">{d["event_count"]}</td>'
                f'<td style="text-align:center; font-family:\'JetBrains Mono\',monospace;">{d["severity"]}</td>'
                f'<td style="text-align:center; font-family:\'JetBrains Mono\',monospace;">{d["likelihood"]}</td>'
                f'<td style="text-align:center; font-family:\'JetBrains Mono\',monospace;">{d["impact"]}</td>'
                f'<td style="text-align:right; font-family:\'JetBrains Mono\',monospace; font-weight:700;">{d["risk"]}</td>'
                f'<td>{render_band_pill(d["band"])}</td>'
                f'<td style="text-align:center; font-family:\'JetBrains Mono\',monospace;">#{d["baseline_rank"]}</td>'
                f'<td style="text-align:center; font-family:\'JetBrains Mono\',monospace; font-weight:700; color:#dce2f7;">#{d["risk_rank"]}</td>'
                f'<td style="text-align:right; font-family:\'JetBrains Mono\',monospace; font-weight:700; color:{s_col};">{arrow}</td>'
                f"</tr>"
            )

        val_df = pd.DataFrame(val_rows)

        st.markdown(
            f"""
            <div class="soc-panel">
                <div class="soc-panel-header">
                    <span style="font-size:1.05rem; font-weight:700; color:#dce2f7;">5.1 Golden Validation Table (Baseline vs. Contextual Risk Ranking)</span>
                    <span class="soc-badge-green">LIVE COMPARISON</span>
                </div>
                <div class="soc-table-wrap">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>SCENARIO</th>
                                <th>ASSET</th>
                                <th>THREAT</th>
                                <th style="text-align:right;">COUNT (n)</th>
                                <th style="text-align:center;">SEV</th>
                                <th style="text-align:center;">L</th>
                                <th style="text-align:center;">I</th>
                                <th style="text-align:right;">RISK</th>
                                <th>BAND</th>
                                <th style="text-align:center;">BASELINE RK</th>
                                <th style="text-align:center;">RISK RK</th>
                                <th style="text-align:right;">SHIFT</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(table_html)}
                        </tbody>
                    </table>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        c_chart1, c_chart2 = st.columns(2)
        with c_chart1:
            colors = ["#4edea3" if s > 0 else ("#ffb4ab" if s < 0 else "#8c909f") for s in val_df["Shift"]]
            fig_shift = go.Figure(
                data=[
                    go.Bar(
                        x=[f"{r['Scenario']} ({r['Asset']})" for r in val_rows],
                        y=val_df["Shift"],
                        marker_color=colors,
                        text=[f"+{s}" if s > 0 else str(s) for s in val_df["Shift"]],
                        textposition="outside",
                        textfont={"family": "JetBrains Mono", "size": 12, "color": "#dce2f7"},
                    )
                ]
            )
            fig_shift.update_layout(
                title="Priority Rank Shift (Shift = Baseline Rank − Risk Rank)",
                paper_bgcolor="#141b2b",
                plot_bgcolor="#141b2b",
                font={"family": "Geist", "color": "#dce2f7"},
                yaxis=dict(title="Rank Change (+ = Moved Up in Priority)", zeroline=True, zerolinecolor="#8c909f"),
                xaxis=dict(title="Scenario & Asset"),
                height=370,
                margin=dict(l=20, r=20, t=45, b=40),
            )
            st.plotly_chart(fig_shift, use_container_width=True)

        with c_chart2:
            fig_comp = go.Figure(
                data=[
                    go.Bar(
                        name="Baseline Rank (Severity + Volume)",
                        x=[f"{r['Scenario']}" for r in val_rows],
                        y=val_df["Baseline rank"],
                        marker_color="#8c909f",
                        text=val_df["Baseline rank"],
                        textposition="auto",
                    ),
                    go.Bar(
                        name="Contextual Risk Rank (L × I)",
                        x=[f"{r['Scenario']}" for r in val_rows],
                        y=val_df["Risk rank"],
                        marker_color="#4d8eff",
                        text=val_df["Risk rank"],
                        textposition="auto",
                    ),
                ]
            )
            fig_comp.update_layout(
                title="Baseline Rank vs. Risk Rank (Lower Number = Higher Priority)",
                barmode="group",
                paper_bgcolor="#141b2b",
                plot_bgcolor="#141b2b",
                font={"family": "Geist", "color": "#dce2f7"},
                yaxis=dict(title="Priority Rank (1 = Highest)", dtick=1),
                xaxis=dict(title="Scenario"),
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
                height=370,
                margin=dict(l=20, r=20, t=65, b=40),
            )
            st.plotly_chart(fig_comp, use_container_width=True)


# =====================================================================
# PAGE 6: AUDIT REPORT GENERATOR (DARK SOC THEME)
# =====================================================================
elif selected_page == "6. Audit Report Generator":
    conn = get_connection()
    try:
        report_md = generate_audit_report_markdown(conn)
    finally:
        conn.close()

    st.markdown(
        f"""
        <div class="soc-banner">
            <div>
                <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.35rem;">
                    <span class="soc-badge-green">SOC STAGE: AUTOMATED AUDIT DELIVERABLE</span>
                    <span style="color:#8c909f;">•</span>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:#c2c6d6;">Section 12 Formal Report</span>
                </div>
                <div style="font-size:1.55rem; font-weight:700; color:#dce2f7;">Automated Security Risk & Audit Report Generator</div>
                <div style="font-size:0.84rem; color:#c2c6d6;">Generates a complete 8-section Markdown audit report directly from live SQLite tables and cryptographic chain verification</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    dl_col1, dl_col2, _ = st.columns([3, 3, 6])
    with dl_col1:
        st.download_button(
            label="📥 Download Markdown Audit Report (.md)",
            data=report_md,
            file_name="risksiem_audit_report.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with dl_col2:
        with st.expander("View Raw Markdown Source", expanded=False):
            st.code(report_md, language="markdown")

    st.markdown('<div class="soc-panel">', unsafe_allow_html=True)
    st.markdown(report_md)
    st.markdown("</div>", unsafe_allow_html=True)
