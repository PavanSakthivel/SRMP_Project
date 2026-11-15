"""RiskSIEM Streamlit Dashboard built with the Dark SOC Executive Template."""

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
from engine.risk import compute_residual_score
from scripts.reset_demo import reset_environment
from scripts.run_pipeline import run_pipeline
from scripts.tamper_demo import tamper_record

st.set_page_config(
    page_title="RiskSIEM | SOC Executive Risk & Audit Layer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject the Dark SOC Template CSS & Fonts
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
    padding-top: 1.5rem !important;
    padding-bottom: 2.5rem !important;
    max-width: 1440px !important;
}

h1, h2, h3, h4 {
    color: var(--on-surface) !important;
    font-family: 'Geist', sans-serif !important;
    letter-spacing: -0.01em;
}

code, pre, .mono {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Custom SOC Cards */
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
    background: var(--surface-container);
    color: var(--tertiary);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    font-weight: 700;
    padding: 0.15rem 0.45rem;
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
    padding: 0.95rem 1.1rem;
    position: relative;
    overflow: hidden;
}

.soc-kpi-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--outline);
    margin-bottom: 0.35rem;
}

.soc-kpi-value {
    font-size: 1.95rem;
    font-weight: 700;
    line-height: 2.25rem;
    margin-bottom: 0.35rem;
}

.soc-kpi-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: var(--on-surface-variant);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.soc-panel {
    background: var(--surface-low);
    border: 1px solid #232a3a;
    border-radius: 0.75rem;
    padding: 1.1rem;
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
    background: #232a3a;
    color: var(--outline);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

table.soc-table th, table.soc-table td {
    padding: 0.55rem 0.65rem;
    text-align: left;
    border-bottom: 1px solid #191f2f;
}

table.soc-table tbody tr:hover {
    background: #232a3a;
}

.band-pill {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    font-weight: 700;
    padding: 0.15rem 0.45rem;
    border-radius: 0.25rem;
    text-transform: uppercase;
    display: inline-block;
}

.band-critical {
    background: rgba(255, 180, 171, 0.16);
    color: #ffb4ab;
    border: 1px solid rgba(255, 180, 171, 0.35);
}

.band-high {
    background: rgba(49, 49, 192, 0.45);
    color: #e1e0ff;
    border: 1px solid rgba(192, 193, 255, 0.35);
}

.band-medium {
    background: #2e3545;
    color: #6ffbbe;
    border: 1px solid rgba(111, 251, 190, 0.3);
}

.band-low {
    background: #191f2f;
    color: #adc6ff;
    border: 1px solid rgba(173, 198, 255, 0.25);
}

/* 5x5 Matrix HTML Grid */
.matrix-grid-5x5 {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 0.3rem;
}

.matrix-cell {
    height: 2.85rem;
    border-radius: 0.3rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.68rem;
    font-weight: 700;
}

.matrix-tag {
    font-size: 0.58rem;
    padding: 0.05rem 0.3rem;
    border-radius: 0.2rem;
    margin-top: -0.1rem;
    background: #0c1322;
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
    padding: 0.9rem 1rem;
    border-left: 4px solid var(--error);
}

.soc-alert-card.secondary-border {
    border-left-color: var(--secondary);
}

div.stButton > button, div.stDownloadButton > button {
    background-color: var(--surface-high) !important;
    color: var(--on-surface) !important;
    border: 1px solid #2e3545 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.76rem !important;
    border-radius: 0.4rem !important;
}

div.stButton > button:hover, div.stDownloadButton > button:hover {
    background-color: var(--primary-container) !important;
    color: #001a42 !important;
    border-color: var(--primary) !important;
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
            cnt = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='detections'").fetchone()[0]
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


def load_dashboard_state() -> dict:
    """Load detections, scores, evidence, issues, and chain status from riskSIEM.db."""
    conn = get_connection()
    try:
        det_rows = conn.execute(
            """
            SELECT d.detection_id, d.threat_id, d.host, d.asset_id, d.source, d.event_count,
                   d.first_seen, d.last_seen, d.details,
                   a.name AS asset_name, a.owner AS asset_owner, a.value AS asset_value,
                   r.impact, r.likelihood, r.freq_bonus, r.risk, r.band, r.severity,
                   r.baseline_rank, r.risk_rank
            FROM detections d
            JOIN risk_scores r ON d.detection_id = r.detection_id
            JOIN assets a ON d.asset_id = a.asset_id
            ORDER BY r.risk_rank ASC
            """
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
        "evidence": [dict(r) for r in ev_rows],
        "issues": [dict(r) for r in issue_rows],
        "logs": [dict(r) for r in log_rows],
        "chain": chain_res,
        "anchor": anchor_data,
    }


state = load_dashboard_state()
chain_info = state["chain"]
head_hash = chain_info.get("head_hash", "0" * 64)
short_head = f"{head_hash[:8]}...{head_hash[-8:]}"
sync_color = "#4edea3" if chain_info["ok"] else "#ffb4ab"
sync_label = "SYNCED" if chain_info["ok"] else "TAMPERED"

# --- SIDEBAR (Template Aesthetic) ---
with st.sidebar:
    st.markdown(
        f"""
        <div style="display:flex; flex-direction:column; gap:0.25rem; margin-bottom:0.85rem;">
            <div style="display:flex; align-items:center; gap:0.5rem;">
                <span style="width:10px; height:10px; border-radius:50%; background:{sync_color}; display:inline-block;"></span>
                <span style="font-size:1.15rem; font-weight:700; color:#adc6ff; letter-spacing:-0.01em;">RiskSIEM</span>
                <span style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; background:#2e3545; color:#d8e2ff; padding:2px 6px; border-radius:4px; font-weight:700;">v3.4-PROD</span>
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

    PAGES = [
        "1. Overview & Risk Matrix",
        "2. Methodology & Catalogs",
        "3. Audit Evidence & Issues",
        "4. Tamper-Evident Log Chain",
        "5. Baseline vs Validation",
        "6. Audit Report Generator",
    ]
    selected_page = st.radio("Navigation Modules", PAGES, label_visibility="collapsed")

    st.markdown(
        """
        <div style="font-family:'JetBrains Mono',monospace; font-size:0.64rem; color:#8c909f; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; margin-top:1rem; margin-bottom:0.4rem;">
            Quick Actions
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("🔄 Reset & Re-ingest (auth.log)", use_container_width=True):
        reset_environment(verbose=False)
        st.session_state["treated_ids"] = set()
        st.rerun()

    if st.button("🔒 Load AC-7 Lockout Log", use_container_width=True):
        run_pipeline(log_path=DATA_DIR / "sample" / "auth_with_lockout.log", verbose=False)
        st.session_state["treated_ids"] = set()
        st.rerun()

    if st.button("⚠️ Run Tamper Demo (ID 150)", use_container_width=True):
        try:
            tamper_record(record_id=150)
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))

    st.markdown(
        f"""
        <div style="margin-top:1rem; padding:0.55rem 0.75rem; background:#070e1d; border:1px solid #232a3a; border-radius:0.4rem; display:flex; justify-content:space-between; align-items:center;">
            <span style="font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#c2c6d6;">SecOps Instance: 04 (Offline)</span>
            <span style="width:8px; height:8px; border-radius:50%; background:{sync_color}; display:inline-block;"></span>
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
# PAGE 1: OVERVIEW & RISK MATRIX
# =====================================================================
if selected_page == "1. Overview & Risk Matrix":
    detections = state["detections"]
    threats_map = load_threats_csv()
    assets_map = load_assets_csv()
    exposure_map = load_exposure_csv()
    treatments_map = load_treatments_csv()

    # Compute display rows (incorporating Stretch "Treat Risk" residual risk state)
    treated_ids: set[int] = st.session_state["treated_ids"]
    display_rows = []
    for d in detections:
        det_id = int(d["detection_id"])
        t_info = threats_map[d["threat_id"]]
        a_info = assets_map[d["asset_id"]]
        orig_exp = exposure_map[d["asset_id"]][d["threat_id"]]
        residual = compute_residual_score(d, a_info, t_info, orig_exp)
        is_treated = det_id in treated_ids
        active_l = residual["likelihood"] if is_treated else int(d["likelihood"])
        active_risk = residual["risk"] if is_treated else int(d["risk"])
        active_band = residual["band"] if is_treated else d["band"]
        shift = int(d["baseline_rank"]) - int(d["risk_rank"])
        display_rows.append(
            {
                **d,
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

    # Top Executive Banner
    st.markdown(
        f"""
        <div class="soc-banner">
            <div>
                <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.3rem;">
                    <span class="soc-badge-green">SOC Stage: Active Triage</span>
                    <span style="color:#8c909f;">•</span>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.72rem; color:#c2c6d6;">Course 21CSC308T / Real-Time Audit Core</span>
                </div>
                <div style="font-size:1.55rem; font-weight:700; color:#dce2f7; letter-spacing:-0.01em;">RiskSIEM Executive Risk & Threat Overview</div>
                <div style="font-size:0.84rem; color:#c2c6d6;">Contextual business-risk ranking on ingested authentication & firewall telemetry (Greenfield Institute of Technology)</div>
            </div>
            <div style="display:flex; align-items:center; gap:0.65rem;">
                <div style="background:#191f2f; border:1px solid #2e3545; padding:0.4rem 0.75rem; border-radius:0.4rem; font-family:'JetBrains Mono',monospace; font-size:0.72rem;">
                    <span style="color:{sync_color};">●</span> Feed Ingest: <strong>{len(state['logs'])} events</strong> | <span style="color:#adc6ff;">2026-11-10 +05:30</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 4 KPI Cards (Template Layout)
    crit_sub = ", ".join(crit_list) if crit_list else "None active"
    hm_summary = f"High: {', '.join(high_list) or '0'} • Med: {', '.join(med_list) or '0'}" + (
        f" • Low: {', '.join(low_list)}" if low_list else ""
    )
    st.markdown(
        f"""
        <div class="soc-kpi-grid">
            <div class="soc-kpi-card" style="border-bottom: 2px solid #adc6ff;">
                <div class="soc-kpi-title">Ingested Detections</div>
                <div class="soc-kpi-value" style="color:#adc6ff;">{len(display_rows)} <span style="font-size:0.75rem; font-family:'JetBrains Mono',monospace; color:#4edea3; font-weight:500;">100% Evaluated</span></div>
                <div class="soc-kpi-sub">
                    <span>Events Scanned: {len(state['logs'])}</span>
                    <span class="soc-badge-green">COMPLETE</span>
                </div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 2px solid #ffb4ab;">
                <div class="soc-kpi-title" style="color:#ffb4ab;">Critical Risk Alerts</div>
                <div class="soc-kpi-value" style="color:#ffb4ab;">{len(crit_list)} <span style="font-size:0.75rem; font-family:'JetBrains Mono',monospace; color:#ffb4ab; font-weight:500;">Band 20-25</span></div>
                <div class="soc-kpi-sub">
                    <span>{crit_sub}</span>
                    <span style="background:#93000a; color:#ffdad6; font-size:0.6rem; padding:2px 5px; border-radius:3px; font-weight:700;">CONTAIN IMMEDIATE</span>
                </div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 2px solid #c0c1ff;">
                <div class="soc-kpi-title">High / Med / Low Alerts</div>
                <div class="soc-kpi-value" style="color:#dce2f7;">{len(high_list)}H / {len(med_list)}M / {len(low_list)}L</div>
                <div class="soc-kpi-sub">
                    <span>{hm_summary}</span>
                    <span style="background:#191f2f; color:#e1e0ff; font-size:0.6rem; padding:2px 5px; border-radius:3px; font-weight:700;">STAGED</span>
                </div>
            </div>
            <div class="soc-kpi-card" style="border-bottom: 2px solid {chain_color};">
                <div class="soc-kpi-title" style="color:{chain_color};">SHA-256 Log Integrity</div>
                <div class="soc-kpi-value" style="color:{chain_color}; font-size:1.3rem;">{chain_title}</div>
                <div class="soc-kpi-sub">
                    <span>{chain_info['checked']} Blocks Checked</span>
                    <span style="background:rgba(78,222,163,0.12); color:{chain_color}; font-size:0.6rem; padding:2px 5px; border-radius:3px; font-weight:700;">{chain_badge}</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Middle Section: Left (Risk-Ranked Detection Queue Table + Stretch Treat Risk) | Right (5x5 Risk Matrix & Plotly Heatmap)
    col_left, col_right = st.columns([8, 4], gap="medium")

    with col_left:
        f_col1, f_col2 = st.columns([6, 6])
        with f_col1:
            band_choice = st.segmented_control(
                "Filter Band",
                options=["ALL", "Critical", "High", "Medium", "Low"],
                default="ALL",
                label_visibility="collapsed",
            )
        with f_col2:
            treat_options = {f"S{r['detection_id']} • {r['host']} ({r['threat_id']})": r["detection_id"] for r in display_rows}
            selected_treat_labels = st.multiselect(
                "Treat Risk (Reduce Exposure by 2 -> Residual Score)",
                options=list(treat_options.keys()),
                default=[k for k, v in treat_options.items() if v in treated_ids],
                placeholder="Select scenario(s) to apply treatment (Stretch Feature)...",
                label_visibility="collapsed",
            )
            new_treated_set = {treat_options[lbl] for lbl in selected_treat_labels}
            if new_treated_set != treated_ids:
                st.session_state["treated_ids"] = new_treated_set
                st.rerun()

        filtered_rows = [
            r
            for r in display_rows
            if not band_choice or band_choice == "ALL" or r["active_band"].lower() == band_choice.lower()
        ]

        table_rows_html = []
        for r in filtered_rows:
            shift_val = r["shift"]
            if shift_val > 0:
                shift_html = f'<span style="color:#4edea3; font-family:\'JetBrains Mono\',monospace;">▲ R{r["baseline_rank"]}→{r["risk_rank"]} (+{shift_val})</span>'
            elif shift_val < 0:
                shift_html = f'<span style="color:#c2c6d6; font-family:\'JetBrains Mono\',monospace;">▼ R{r["baseline_rank"]}→{r["risk_rank"]} ({shift_val})</span>'
            else:
                shift_html = f'<span style="color:#8c909f; font-family:\'JetBrains Mono\',monospace;">● R{r["baseline_rank"]}→{r["risk_rank"]} (0)</span>'

            if r["is_treated"]:
                l_cell = f'<span style="color:#8c909f; text-decoration:line-through;">{r["likelihood"]}</span> → <strong style="color:#4edea3;">{r["residual_l"]}</strong>'
                risk_cell = f'<span style="color:#8c909f; text-decoration:line-through;">{r["risk"]}</span> → <strong style="color:#4edea3;">{r["residual_risk"]}</strong>'
                band_cell = f'{render_band_pill(r["band"])} → {render_band_pill(r["residual_band"])}'
                status_badge = '<span style="background:#4edea3; color:#003824; font-family:\'JetBrains Mono\',monospace; font-size:0.62rem; font-weight:700; padding:2px 6px; border-radius:3px;">TREATED (-2 EXP)</span>'
            else:
                l_cell = f'{r["likelihood"]}'
                risk_color = "#ffb4ab" if r["risk"] >= 20 else ("#c0c1ff" if r["risk"] >= 12 else "#6ffbbe")
                risk_cell = f'<strong style="color:{risk_color}; font-size:0.9rem;">{r["risk"]}</strong> <span style="color:#8c909f; font-size:0.7rem;">(Res: {r["residual_risk"]})</span>'
                band_cell = render_band_pill(r["band"])
                status_badge = f'<span style="background:#2e3545; color:#dce2f7; font-family:\'JetBrains Mono\',monospace; font-size:0.62rem; padding:2px 6px; border-radius:3px;">EXP={r["orig_exposure"]}</span>'

            rank_bg = "#93000a" if r["risk_rank"] <= 2 else "#2e3545"
            rank_fg = "#ffdad6" if r["risk_rank"] <= 2 else "#dce2f7"

            table_rows_html.append(
                f"<tr>"
                f'<td><span style="display:inline-flex; align-items:center; justify-content:center; width:22px; height:22px; border-radius:4px; background:{rank_bg}; color:{rank_fg}; font-family:\'JetBrains Mono\',monospace; font-size:0.72rem; font-weight:700;">{r["risk_rank"]}</span></td>'
                f'<td><div style="font-family:\'JetBrains Mono\',monospace; font-weight:600; color:#dce2f7;">S{r["detection_id"]} • {r["host"]}</div><div style="font-size:0.72rem; color:#c2c6d6;">{r["asset_id"]} — {r["asset_name"]}</div></td>'
                f'<td><div style="font-family:\'JetBrains Mono\',monospace; color:#adc6ff;">{r["threat_id"]}</div><div style="font-size:0.72rem; color:#8c909f;">{r["threat_name"]}</div></td>'
                f'<td style="text-align:right; font-family:\'JetBrains Mono\',monospace;">{r["event_count"]}</td>'
                f'<td style="text-align:center; font-family:\'JetBrains Mono\',monospace; font-weight:700;">{r["severity"]}</td>'
                f'<td style="text-align:center; font-family:\'JetBrains Mono\',monospace;">{l_cell}</td>'
                f'<td style="text-align:center; font-family:\'JetBrains Mono\',monospace;">{r["impact"]}</td>'
                f'<td style="text-align:right; font-family:\'JetBrains Mono\',monospace;">{risk_cell}</td>'
                f"<td>{band_cell}</td>"
                f"<td>{shift_html}</td>"
                f'<td style="text-align:right;">{status_badge}</td>'
                f"</tr>"
            )

        st.markdown(
            f"""
            <div class="soc-panel">
                <div class="soc-panel-header">
                    <div style="display:flex; align-items:center; gap:0.5rem;">
                        <span style="font-size:1.05rem; font-weight:600; color:#dce2f7;">Risk-Ranked Detection Queue</span>
                        <span style="font-family:'JetBrains Mono',monospace; font-size:0.62rem; background:rgba(173,198,255,0.12); color:#adc6ff; padding:2px 6px; border-radius:4px; font-weight:700;">DYNAMIC SORT (L × I)</span>
                    </div>
                    <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:#4edea3;">Algorithm: GIT-RiskMatrix-v3</span>
                </div>
                <div class="soc-table-wrap">
                    <table class="soc-table">
                        <thead>
                            <tr>
                                <th>Rank</th>
                                <th>Scenario / Asset</th>
                                <th>Threat & MITRE</th>
                                <th style="text-align:right;">Count</th>
                                <th style="text-align:center;">Sev</th>
                                <th style="text-align:center;">L</th>
                                <th style="text-align:center;">I</th>
                                <th style="text-align:right;">Risk (L×I)</th>
                                <th>Band</th>
                                <th>Shift</th>
                                <th style="text-align:right;">Exposure / Treat</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(table_rows_html)}
                        </tbody>
                    </table>
                </div>
                <div style="margin-top:0.6rem; display:flex; justify-content:space-between; font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:#8c909f;">
                    <span>* L (Likelihood: 1-5) × I (Asset Impact: 1-5). Use the multiselect above to apply "Treat Risk" (reduces exposure by 2, min 1).</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        b_col1, b_col2, _ = st.columns([2, 2, 4])
        with b_col1:
            if st.button("🛡️ Treat All Risks (-2 Exposure)", use_container_width=True):
                st.session_state["treated_ids"] = {int(r["detection_id"]) for r in display_rows}
                st.rerun()
        with b_col2:
            if st.button("↩️ Reset Treatments", use_container_width=True):
                st.session_state["treated_ids"] = set()
                st.rerun()

    with col_right:
        # Build Plotly 5x5 Risk Heatmap as required by Section 10.1 + Template's 5x5 matrix aesthetic
        coord_labels: dict[tuple[int, int], list[str]] = {}
        for r in display_rows:
            coord = (int(r["active_l"]), int(r["impact"]))
            coord_labels.setdefault(coord, []).append(f"S{r['detection_id']}")

        z_matrix = []
        text_matrix = []
        for l_val in range(1, 6):
            row_z = []
            row_txt = []
            for i_val in range(1, 6):
                score_val = l_val * i_val
                row_z.append(score_val)
                scen_list = coord_labels.get((l_val, i_val), [])
                if scen_list:
                    row_txt.append(f"{score_val}<br><b>{', '.join(scen_list)}</b>")
                else:
                    row_txt.append(f"{score_val}")
            z_matrix.append(row_z)
            text_matrix.append(row_txt)

        colorscale = [
            [0.0, "#191f2f"],
            [0.20, "#232a3a"],
            [0.24, "#1f3a3d"],
            [0.44, "#284b52"],
            [0.48, "#3131c0"],
            [0.76, "#4647d4"],
            [0.80, "#93000a"],
            [1.0, "#c62828"],
        ]

        fig_hm = go.Figure(
            data=go.Heatmap(
                z=z_matrix,
                x=["I:1", "I:2", "I:3", "I:4", "I:5"],
                y=["L:1", "L:2", "L:3", "L:4", "L:5"],
                text=text_matrix,
                texttemplate="%{text}",
                textfont={"family": "JetBrains Mono", "size": 11, "color": "#dce2f7"},
                colorscale=colorscale,
                zmin=1,
                zmax=25,
                showscale=False,
                hovertemplate="Likelihood: %{y}<br>Impact: %{x}<br>Risk Score: %{z}<extra></extra>",
            )
        )
        fig_hm.update_layout(
            title={
                "text": "5×5 Likelihood vs. Impact Matrix",
                "font": {"family": "Geist", "size": 15, "color": "#dce2f7"},
                "x": 0.0,
            },
            paper_bgcolor="#141b2b",
            plot_bgcolor="#141b2b",
            margin=dict(l=10, r=10, t=40, b=10),
            height=330,
            xaxis=dict(title="Impact: Asset Sensitivity (1 - 5)", color="#c2c6d6", fixedrange=True),
            yaxis=dict(title="Likelihood (1 - 5)", color="#c2c6d6", fixedrange=True),
        )
        st.plotly_chart(fig_hm, use_container_width=True)

        st.markdown(
            """
            <div class="soc-panel" style="padding:0.85rem;">
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:0.4rem; font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#c2c6d6; margin-bottom:0.65rem;">
                    <div><span style="display:inline-block;width:10px;height:10px;background:#191f2f;border:1px solid #adc6ff;margin-right:6px;"></span>Low (1-5)</div>
                    <div><span style="display:inline-block;width:10px;height:10px;background:#284b52;border:1px solid #6ffbbe;margin-right:6px;"></span>Medium (6-11)</div>
                    <div><span style="display:inline-block;width:10px;height:10px;background:#3131c0;border:1px solid #c0c1ff;margin-right:6px;"></span>High (12-19)</div>
                    <div><span style="display:inline-block;width:10px;height:10px;background:#93000a;border:1px solid #ffb4ab;margin-right:6px;"></span>Critical (20-25)</div>
                </div>
                <div style="background:#070e1d; padding:0.6rem; border-radius:0.4rem; font-size:0.76rem; color:#c2c6d6;">
                    <div style="display:flex; justify-content:space-between; font-family:'JetBrains Mono',monospace; font-size:0.68rem; margin-bottom:0.2rem;">
                        <span style="color:#8c909f;">Cluster Density</span>
                        <span style="color:#4edea3; font-weight:700;">Concentrated (Top-Right)</span>
                    </div>
                    Critical assets (<code style="color:#ffb4ab;">S2, S4</code>) gravitate towards Top-Right quadrant due to maximum institutional asset weights (<code style="color:#adc6ff;">I=5</code>).
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Bottom Section: Live Ingestion Summary & Quick Control Failures (Template Cards)
    st.markdown(
        """
        <div class="soc-panel">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.85rem; flex-wrap:wrap;">
                <div>
                    <div style="font-size:1.05rem; font-weight:600; color:#dce2f7;">⚠️ Live Ingestion Summary & Quick Control Failures</div>
                    <div style="font-size:0.78rem; color:#c2c6d6;">NIST SP 800-53 & CIS v8 security control deviations parsed from syslog event streams</div>
                </div>
            </div>
            <div class="alert-grid-3">
                <div class="soc-alert-card">
                    <div style="display:flex; justify-content:space-between; margin-bottom:0.35rem;">
                        <span style="background:#93000a; color:#ffdad6; font-family:'JetBrains Mono',monospace; font-size:0.62rem; font-weight:700; padding:2px 6px; border-radius:3px;">AC-7 / CIS 5 FAILED</span>
                        <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:#8c909f;">pay-srv-01 & gw-01</span>
                    </div>
                    <div style="font-weight:600; font-size:0.88rem; margin-bottom:0.25rem;">Unenforced Lockout Policy</div>
                    <div style="font-size:0.76rem; color:#c2c6d6; margin-bottom:0.45rem;">
                        No account lockout line observed within 120s after 12 failed SSH attempts on <code style="color:#adc6ff;">pay-srv-01</code> (S4) and 40 attempts on <code style="color:#adc6ff;">gw-01</code> (S3).
                    </div>
                    <div style="display:flex; justify-content:space-between; font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#8c909f;">
                        <span>Threat: T1110</span>
                        <span style="color:#ffb4ab; font-weight:700;">Risk: 20 (Critical)</span>
                    </div>
                </div>
                <div class="soc-alert-card">
                    <div style="display:flex; justify-content:space-between; margin-bottom:0.35rem;">
                        <span style="background:#93000a; color:#ffdad6; font-family:'JetBrains Mono',monospace; font-size:0.62rem; font-weight:700; padding:2px 6px; border-radius:3px;">AC-6 / CIS 6 FAILED</span>
                        <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:#8c909f;">db-srv-01 & ws-lab-01</span>
                    </div>
                    <div style="font-weight:600; font-size:0.88rem; margin-bottom:0.25rem;">Least Privilege Breach</div>
                    <div style="font-size:0.76rem; color:#c2c6d6; margin-bottom:0.45rem;">
                        Unauthorised sudo elevation to <code style="color:#ffb4ab;">root</code> executed by non-admin users <code style="color:#adc6ff;">'bob'</code> (S2) and <code style="color:#adc6ff;">'carol'</code> (S1).
                    </div>
                    <div style="display:flex; justify-content:space-between; font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#8c909f;">
                        <span>Threat: T1548</span>
                        <span style="color:#ffb4ab; font-weight:700;">Risk: 20 (Critical)</span>
                    </div>
                </div>
                <div class="soc-alert-card secondary-border">
                    <div style="display:flex; justify-content:space-between; margin-bottom:0.35rem;">
                        <span style="background:#3131c0; color:#e1e0ff; font-family:'JetBrains Mono',monospace; font-size:0.62rem; font-weight:700; padding:2px 6px; border-radius:3px;">SC-7 / CIS 13 FAILED</span>
                        <span style="font-family:'JetBrains Mono',monospace; font-size:0.7rem; color:#8c909f;">exam-srv-01 & gw-01</span>
                    </div>
                    <div style="font-weight:600; font-size:0.88rem; margin-bottom:0.25rem;">Boundary Protection Ingress</div>
                    <div style="font-size:0.76rem; color:#c2c6d6; margin-bottom:0.45rem;">
                        15 rapid port scans detected against <code style="color:#adc6ff;">exam-srv-01</code> (S6) and <code style="color:#adc6ff;">gw-01</code> (S5) within 28s window (blocked by UFW, unthrottled).
                    </div>
                    <div style="display:flex; justify-content:space-between; font-family:'JetBrains Mono',monospace; font-size:0.68rem; color:#8c909f;">
                        <span>Threat: T1046</span>
                        <span style="color:#c0c1ff; font-weight:700;">Risk: 12 (High)</span>
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# =====================================================================
# PAGE 2: METHODOLOGY & CATALOGS
# =====================================================================
elif selected_page == "2. Methodology & Catalogs":
    st.markdown(
        """
        <div class="soc-banner">
            <div>
                <div style="margin-bottom:0.25rem;"><span class="soc-badge-green">Unit 2 & Unit 3 Architecture</span></div>
                <div style="font-size:1.5rem; font-weight:700; color:#dce2f7;">Risk Scoring Methodology & Reference Catalogs</div>
                <div style="font-size:0.84rem; color:#c2c6d6;">Greenfield Institute of Technology (GIT) — Asset Inventory, Threat & Vulnerability Catalogs, TV Pairs, Exposure Matrix & Worked Example</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.info(
        "**Assessor Assumption Note:** Asset business values (1–5), Confidentiality/Integrity/Availability (CIA) ratings (1–5), "
        "and per-asset vulnerability exposure scores (1–5) are assessor-assigned from the fictional Greenfield Institute of Technology "
        "organisation profile and represent structured risk assessment assumptions rather than empirical telemetry measurements."
    )

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("2.1 Asset Inventory (`data/assets.csv`)")
        assets_df = pd.read_csv(DATA_DIR / "assets.csv")
        st.dataframe(assets_df, use_container_width=True, hide_index=True)

        st.subheader("2.2 Threat Catalog (`data/threats.csv`)")
        threats_df = pd.read_csv(DATA_DIR / "threats.csv")
        st.dataframe(threats_df, use_container_width=True, hide_index=True)

        st.subheader("2.3 Vulnerability Catalog (`data/vulnerabilities.csv`)")
        vulns_df = pd.read_csv(DATA_DIR / "vulnerabilities.csv")
        st.dataframe(vulns_df, use_container_width=True, hide_index=True)

    with c2:
        st.subheader("2.4 Threat–Vulnerability Pairs (`data/tv_pairs.csv`)")
        tv_pairs = load_tv_pairs_csv()
        threats_map = load_threats_csv()
        vulns_map = load_vulnerabilities_csv()
        tv_enriched = [
            {
                "threat_id": p["threat_id"],
                "threat_name": threats_map[p["threat_id"]]["name"],
                "vuln_id": p["vuln_id"],
                "vuln_name": vulns_map[p["vuln_id"]]["name"],
                "description": vulns_map[p["vuln_id"]]["description"],
            }
            for p in tv_pairs
        ]
        st.dataframe(pd.DataFrame(tv_enriched), use_container_width=True, hide_index=True)

        st.subheader("2.5 Vulnerability Exposure per Asset (`data/exposure.csv`)")
        exp_df = pd.read_csv(DATA_DIR / "exposure.csv")
        st.dataframe(exp_df, use_container_width=True, hide_index=True)

        st.subheader("2.6 Control Mapping (`data/control_map.csv`)")
        ctrl_df = pd.read_csv(DATA_DIR / "control_map.csv")
        st.dataframe(ctrl_df, use_container_width=True, hide_index=True)

    st.subheader("2.7 Scoring Formulas & Worked Example")
    st.markdown(
        r"""
        Using deterministic rounding helper $\text{round\_half\_up}(x) = \lfloor x + 0.5 \rfloor$:

        1. **Impact ($I$):**
           $$I = \text{clamp}\left(\text{round\_half\_up}\left(\frac{A.\text{value} + A.\text{rating}[T.\text{primary\_dimension}]}{2}\right), 1, 5\right)$$
        2. **Frequency Bonus ($F$):**
           - **T1110 (Brute Force):** $n < 20 \Rightarrow 0$, $20 \le n \le 39 \Rightarrow 0.5$, $n \ge 40 \Rightarrow 1.0$
           - **T1046 (Port Scan):** $n < 25 \Rightarrow 0$, $25 \le n \le 49 \Rightarrow 0.5$, $n \ge 50 \Rightarrow 1.0$
           - **T1548 (Privilege Escalation):** always $0$
        3. **Likelihood ($L$):**
           $$L = \min\left(5, \max\left(1, \text{round\_half\_up}\left(\frac{T.\text{base\_likelihood} + \text{exposure}[A][T]}{2} + F\right)\right)\right)$$
        4. **Risk Score ($R$):** $R = L \times I$ (range $1\text{–}25$)
        5. **Risk Band:** **20–25 Critical**, **12–19 High**, **6–11 Medium**, **1–5 Low**.

        ---
        #### Worked Example: Why S4 (`pay-srv-01`, 12 attempts) Outranks S3 (`gw-01`, 40 attempts)
        - **S3 (`gw-01` Guest Wi-Fi Gateway, Asset A6, Threat T1110, $n=40$):**
          - $A.\text{value} = 2$, $A.C = 1 \implies I = \text{round\_half\_up}((2 + 1)/2) = \text{round\_half\_up}(1.5) = 2$
          - $T.\text{base\_likelihood} = 4$, $\text{exposure}[A6][T1110] = 5$, $F = 1.0$ (since $n=40 \ge 40$)
          - $L = \min(5, \text{round\_half\_up}((4 + 5)/2 + 1.0)) = \min(5, 6) = 5$
          - $\text{Risk } R = 5 \times 2 = \mathbf{10\text{ (Medium)}}$
        - **S4 (`pay-srv-01` Payroll Server, Asset A2, Threat T1110, $n=12$):**
          - $A.\text{value} = 5$, $A.C = 5 \implies I = \text{round\_half\_up}((5 + 5)/2) = 5$
          - $T.\text{base\_likelihood} = 4$, $\text{exposure}[A2][T1110] = 4$, $F = 0.0$ (since $n=12 < 20$)
          - $L = \text{round\_half\_up}((4 + 4)/2 + 0) = 4$
          - $\text{Risk } R = 4 \times 5 = \mathbf{20\text{ (Critical)}}$
        """
    )


# =====================================================================
# PAGE 3: AUDIT EVIDENCE & ISSUES REGISTER
# =====================================================================
elif selected_page == "3. Audit Evidence & Issues":
    evidence = state["evidence"]
    issues = state["issues"]

    direct_count = sum(1 for e in evidence if e["type"] == "direct")
    indirect_count = sum(1 for e in evidence if e["type"] == "indirect")

    st.markdown(
        f"""
        <div class="soc-banner">
            <div>
                <div style="margin-bottom:0.25rem;"><span class="soc-badge-green">Unit 4 & Unit 5 Compliance Core</span></div>
                <div style="font-size:1.5rem; font-weight:700; color:#dce2f7;">Audit Evidence & Issues Register</div>
                <div style="font-size:0.84rem; color:#c2c6d6;">Direct log evidence linked to SHA-256 chain hashes, indirect analytical evidence, NIST SP 800-53 / CIS v8 control tests, and formal Issues Register</div>
            </div>
            <div style="font-family:'JetBrains Mono',monospace; font-size:0.78rem; background:#191f2f; padding:0.5rem 0.85rem; border-radius:0.5rem; border:1px solid #2e3545;">
                Direct: <strong style="color:#adc6ff;">{direct_count}</strong> | Indirect: <strong style="color:#4edea3;">{indirect_count}</strong> | Open Issues: <strong style="color:#ffb4ab;">{len(issues)}</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.subheader("3.1 Issues Register (`issues` table)")
    if not issues:
        st.success("0 open issues in the Issues Register (all evaluated security controls passed!).")
    else:
        issues_df = pd.DataFrame(issues)
        st.dataframe(issues_df, use_container_width=True, hide_index=True)

    issues_csv_buf = io.StringIO()
    pd.DataFrame(issues).to_csv(issues_csv_buf, index=False)
    st.download_button(
        label="📥 Download Issues Register (issues.csv)",
        data=issues_csv_buf.getvalue(),
        file_name="issues.csv",
        mime="text/csv",
    )

    st.divider()
    st.subheader("3.2 Audit Evidence Explorer (`evidence` table)")

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

    ev_df = pd.DataFrame(filtered_ev)
    st.dataframe(ev_df, use_container_width=True, hide_index=True)

    ev_csv_buf = io.StringIO()
    pd.DataFrame(evidence).to_csv(ev_csv_buf, index=False)
    st.download_button(
        label="📥 Download Full Evidence Table (evidence.csv)",
        data=ev_csv_buf.getvalue(),
        file_name="evidence.csv",
        mime="text/csv",
    )


# =====================================================================
# PAGE 4: TAMPER-EVIDENT LOG CHAIN (INTEGRITY)
# =====================================================================
elif selected_page == "4. Tamper-Evident Log Chain":
    st.markdown(
        """
        <div class="soc-banner">
            <div>
                <div style="margin-bottom:0.25rem;"><span class="soc-badge-green">NIST AU-9 / CIS Control 8</span></div>
                <div style="font-size:1.5rem; font-weight:700; color:#dce2f7;">Tamper-Evident SHA-256 Log Chain & External Anchor</div>
                <div style="font-size:0.84rem; color:#c2c6d6;">Cryptographic hash chaining across every ingested log event with external anchor verification (anchor/head.txt)</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    btn_c1, btn_c2, btn_c3 = st.columns([2, 2, 2])
    with btn_c1:
        verify_clicked = st.button("🔍 Verify Integrity Now", use_container_width=True)
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

    conn = get_connection()
    try:
        live_verify = verify_chain(conn)
    finally:
        conn.close()

    if live_verify["ok"]:
        st.markdown(
            f"""
            <div style="background:rgba(78,222,163,0.12); border:2px solid #4edea3; border-radius:0.75rem; padding:1.2rem 1.5rem; margin:0.75rem 0;">
                <div style="font-size:1.3rem; font-weight:700; color:#4edea3; margin-bottom:0.35rem;">
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
                <div style="font-size:1.3rem; font-weight:700; color:#ffb4ab; margin-bottom:0.35rem;">
                    🚨 TAMPERING DETECTED AT RECORD ID {live_verify['first_broken_id']}
                </div>
                <div style="font-family:'JetBrains Mono',monospace; font-size:0.82rem; color:#ffdad6;">
                    Reason: <strong>{live_verify['reason']}</strong> (Checked {live_verify['checked']} blocks before failure)
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    anchor_obj = live_verify.get("anchor") or {}
    c_left, c_right = st.columns(2)
    with c_left:
        st.subheader("Cryptographic Chain State")
        st.code(
            f"Genesis Hash    : {'0' * 64}\n"
            f"Recomputed Head : {live_verify['head_hash']}\n"
            f"Records Checked : {live_verify['checked']}\n"
            f"Status          : {live_verify['reason']}",
            language="text",
        )
    with c_right:
        st.subheader("External Anchor (`anchor/head.txt`)")
        st.code(json.dumps(anchor_obj, indent=2), language="json")

    st.subheader("Stored Log Chain (`log_events` table)")
    logs_df = pd.DataFrame(state["logs"])
    if not live_verify["ok"] and live_verify["first_broken_id"] is not None:
        broken_id = int(live_verify["first_broken_id"])
        broken_rows = logs_df[logs_df["id"] == broken_id]
        if not broken_rows.empty:
            st.warning(f"Inspecting tampered record `id = {broken_id}`:")
            st.dataframe(broken_rows, use_container_width=True, hide_index=True)

    st.dataframe(logs_df, use_container_width=True, hide_index=True, height=320)

    st.info(
        "**Control Mapping & Architectural Limitation (NIST AU-9 / CIS Control 8):** "
        "Every log event is chained via `sha256(prev_hash + '|' + timestamp + '|' + host + '|' + raw_line)`. "
        "Anchoring the head hash and row count to `anchor/head.txt` detects database truncation and full-chain rewrites. "
        "**Known Limitation:** An attacker with privileged write access to both `riskSIEM.db` and the local `anchor/head.txt` "
        "file could recompute the chain and overwrite both files. In a production deployment, the anchor file must be stored "
        "on a separate, write-protected/WORM syslog collector or published to an external append-only ledger."
    )


# =====================================================================
# PAGE 5: BASELINE VS. RISK VALIDATION
# =====================================================================
elif selected_page == "5. Baseline vs Validation":
    detections = sorted(state["detections"], key=lambda x: int(x["detection_id"]))

    st.markdown(
        """
        <div class="soc-banner">
            <div>
                <div style="margin-bottom:0.25rem;"><span class="soc-badge-green">Grading Validation Module</span></div>
                <div style="font-size:1.5rem; font-weight:700; color:#dce2f7;">Baseline (Plain-Severity) vs. Contextual Risk Ranking Validation</div>
                <div style="font-size:0.84rem; color:#c2c6d6;">Side-by-side comparison demonstrating how business asset criticality and exposure shift alert triage priority across S1–S6</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    val_rows = []
    for d in detections:
        shift = int(d["baseline_rank"]) - int(d["risk_rank"])
        arrow = f"▲ +{shift}" if shift > 0 else (f"▼ {shift}" if shift < 0 else "● 0")
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
    val_df = pd.DataFrame(val_rows)

    st.subheader("5.1 Golden Validation Table (Section 11 Reproduction)")
    st.dataframe(
        val_df[
            [
                "Scenario",
                "Asset",
                "Threat",
                "n",
                "Severity",
                "L",
                "I",
                "Risk",
                "Band",
                "Baseline rank",
                "Risk rank",
                "Rank Shift",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

    c_chart1, c_chart2 = st.columns(2)
    with c_chart1:
        colors = ["#4edea3" if s > 0 else "#ffb4ab" for s in val_df["Shift"]]
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
            yaxis=dict(title="Rank Change (+ = Moved Up in Priority)", zeroline=True, zerolinecolor="#8c909f", range=[-4, 4]),
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
                    x=[f"{r['Scenario']} ({r['Asset'].split()[1]})" for r in val_rows],
                    y=val_df["Baseline rank"],
                    marker_color="#8c909f",
                    text=val_df["Baseline rank"],
                    textposition="auto",
                ),
                go.Bar(
                    name="Contextual Risk Rank (L × I)",
                    x=[f"{r['Scenario']} ({r['Asset'].split()[1]})" for r in val_rows],
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

    st.subheader("5.2 Generated Validation Summary")
    st.markdown(
        """
        - **Headline Finding — Brute-Force Pair (S4 vs. S3):**
          - **Payroll Server (`pay-srv-01`, S4, 12 failed attempts)** moved from **Baseline Rank 4 to Risk Rank 2 (`+2`)** with a Critical Risk Score of **20** ($L=4, I=5$).
          - **Guest Wi-Fi Gateway (`gw-01`, S3, 40 failed attempts)** moved down from **Baseline Rank 3 to Risk Rank 5 (`-2`)** with a Medium Risk Score of **10** ($L=5, I=2$).
          - *Why:* Plain severity-and-volume ranking prioritizes S3 because 40 failed logins exceed 12 failed logins. RiskSIEM recognizes that `pay-srv-01` has maximum business value and confidentiality ($I=5$), whereas `gw-01` is an isolated guest network gateway ($I=2$).
        - **Privilege Escalation Pair (S2 vs. S1):**
          - **Student Records Database (`db-srv-01`, S2)** moved up from **Baseline Rank 2 to Risk Rank 1 (`+1`, Critical Risk = 20)**, while **Computer Lab Workstation (`ws-lab-01`, S1)** moved down from **Baseline Rank 1 to Risk Rank 4 (`-3`, High Risk = 12)**.
          - *Why:* Both events have severity 5 and count 1, and S1 occurred 15 minutes earlier (`08:40` vs `08:55`), putting S1 #1 in baseline triage. Risk scoring elevates `db-srv-01` ($I=5$) above the low-criticality lab workstation ($I=3$).
        - **Port Scan Pair (S6 vs. S5):**
          - **Online Exam Server (`exam-srv-01`, S6, 15 ports)** surged from **Baseline Rank 6 to Risk Rank 3 (`+3`, High Risk = 12)**, whereas **Guest Wi-Fi Gateway (`gw-01`, S5, 15 ports)** dropped from **Baseline Rank 5 to Risk Rank 6 (`-1`, Medium Risk = 8)**.
        """
    )


# =====================================================================
# PAGE 6: AUDIT REPORT GENERATOR
# =====================================================================
elif selected_page == "6. Audit Report Generator":
    st.markdown(
        """
        <div class="soc-banner">
            <div>
                <div style="margin-bottom:0.25rem;"><span class="soc-badge-green">Section 12 Deliverable</span></div>
                <div style="font-size:1.5rem; font-weight:700; color:#dce2f7;">Automated Security Risk & Audit Report Generator</div>
                <div style="font-size:0.84rem; color:#c2c6d6;">Generates a complete 8-section Markdown audit report directly from live SQLite tables and cryptographic chain verification</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    conn = get_connection()
    try:
        report_md = generate_audit_report_markdown(conn)
    finally:
        conn.close()

    st.download_button(
        label="📥 Download Markdown Audit Report (risksiem_audit_report.md)",
        data=report_md,
        file_name="risksiem_audit_report.md",
        mime="text/markdown",
    )

    with st.expander("View Raw Markdown Source", expanded=False):
        st.code(report_md, language="markdown")

    st.markdown("---")
    st.markdown(report_md)
