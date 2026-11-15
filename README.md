# RiskSIEM: Business-Risk-Scored SIEM & Audit Layer

**Course:** Security Risk Management Principles (`21CSC308T`)  
**Subject Organisation:** Greenfield Institute of Technology (GIT)

RiskSIEM is a lightweight, deterministic, fully local security risk and audit layer built on top of system authentication (`sshd`, `sudo`, `pam_tally2`) and firewall (`UFW`) logs. Instead of sorting alerts solely by static rule severity or raw event volume, RiskSIEM translates detections into:

1. **Contextual Business-Risk Scores ($R = L \times I$):** Combining asset business criticality, CIA requirement ratings, MITRE ATT&CK threat parameters, per-asset vulnerability exposure, and event frequency bonuses.
2. **Audit Evidence & Issues Register:** Automatically generating **direct evidence** (raw log records linked to their cryptographic SHA-256 chain hashes) and **indirect evidence** (correlation conclusions and risk score records), testing **NIST SP 800-53 Rev. 5** and **CIS Controls v8** controls (`AC-7`, `SC-7`, `AC-6`, `AU-9`), and recording failed controls in a formal Issues Register.
3. **Tamper-Evident SHA-256 Log Chain:** Every ingested log event is chained (`sha256(prev_hash + "|" + timestamp + "|" + host + "|" + raw_line)`) and anchored to `anchor/head.txt` (`head_history.log`), detecting unauthorized edits, row deletions, reordering, or truncation.
4. **Baseline vs. Risk Validation:** Demonstrates how contextual business-risk ranking shifts alert priority compared to plain severity-and-volume ranking across six scenarios (`S1`–`S6`).

---

## Installation & Quick Start

```bash
# 1. Install dependencies (Python 3.10+)
pip install -r requirements.txt

# 2. Generate deterministic synthetic log datasets (seeded with random.seed(42))
python scripts/generate_logs.py

# 3. Run the end-to-end RiskSIEM pipeline (ingest -> detect -> score -> evidence -> issues)
python scripts/run_pipeline.py

# 4. Launch the interactive Dark SOC Streamlit Dashboard
python -m streamlit run dashboard/app.py

# 5. Run the automated pytest verification suite
python -m pytest -v
```

### Tamper & Reset Demo Commands

```bash
# Tamper with stored log record ID 150 in riskSIEM.db without recomputing hashes
python scripts/tamper_demo.py

# Delete database & anchor and restore a clean verified state
python scripts/reset_demo.py
```

---

## Project Structure

```text
risksiem/
├── README.md
├── requirements.txt            # streamlit, pandas, plotly, pytest (pinned)
├── pytest.ini                  # pytest configuration
├── data/
│   ├── assets.csv              # GIT asset inventory (A1-A6) with value & C/I/A ratings
│   ├── threats.csv             # Threat catalog (T1110, T1046, T1548)
│   ├── vulnerabilities.csv     # Vulnerability catalog (V1-V4)
│   ├── tv_pairs.csv            # Threat-vulnerability pairs
│   ├── exposure.csv            # Per-asset vulnerability exposure matrix (1-5)
│   ├── control_map.csv         # NIST SP 800-53 & CIS v8 control mappings
│   ├── treatments.csv          # Recommended risk treatments per threat
│   └── sample/
│       ├── auth.log            # Main synthetic log with S1-S6 + benign noise (157 lines)
│       └── auth_with_lockout.log # Brute-force burst followed by pam_tally2 lockout (AC-7 pass)
├── anchor/                     # Runtime chain head anchor (head.txt, head_history.log)
├── engine/
│   ├── __init__.py
│   ├── db.py                   # SQLite connection, schema creation, CSV loaders
│   ├── parse.py                # Regex parser for the 6 syslog formats
│   ├── ingest.py               # Parse + insert + SHA-256 chain + anchor writer
│   ├── chain.py                # SHA-256 hash chain computation, verifier, anchor reader
│   ├── detect.py               # Pure detection rules R1 (T1110), R2 (T1046), R3 (T1548)
│   ├── risk.py                 # Impact, Frequency Bonus, Likelihood, Risk, Ranks, Residual Risk
│   └── evidence.py             # Direct/indirect evidence, control tests, issues register, report
├── scripts/
│   ├── generate_logs.py        # Deterministic log generator (random.seed(42))
│   ├── run_pipeline.py         # Idempotent end-to-end pipeline runner
│   ├── tamper_demo.py          # Modifies raw_line on record ID 150 to demonstrate tamper detection
│   └── reset_demo.py           # Removes DB/anchor and re-runs full ingestion
├── dashboard/
│   └── app.py                  # Dark SOC Streamlit dashboard (6 modules + Stretch Treat Risk)
├── tests/
│   ├── test_parse.py           # Parser & malformed line tests
│   ├── test_detect.py          # S1-S6 detection & benign noise tests
│   ├── test_risk.py            # Golden table (Section 11) & round_half_up tests
│   ├── test_chain.py           # Intact chain, edit, deletion, and anchor mismatch tests
│   └── test_evidence.py        # Issues count (6 main, 0 lockout) & direct evidence count tests
└── docs/
    ├── methodology.md          # Complete risk scoring & control testing methodology
    ├── limitations.md          # Known technical and methodological limitations
    ├── assumptions.md          # Design choices made where specification was silent
    ├── report_outline.md       # Course unit (Units 2-5) & CO-1..CO-5 report template
    └── demo_script.md          # 5-minute live grading demonstration script
```

---

## Screenshots Placeholder

- `docs/screenshots/01_overview_risk_matrix.png` — *Module 1: Executive Risk-Ranked Queue, 5×5 Risk Matrix Heatmap, and Treat Risk Residual Calculator.*
- `docs/screenshots/02_methodology_catalogs.png` — *Module 2: Asset Inventory, TV Pairs, Exposure Matrix, and Worked Example.*
- `docs/screenshots/03_evidence_issues.png` — *Module 3: Direct/Indirect Evidence Explorer and Open Issues Register.*
- `docs/screenshots/04_integrity_tamper_detected.png` — *Module 4: Tamper-Evident SHA-256 Log Chain showing Record #150 Hash Mismatch.*
- `docs/screenshots/05_validation_rank_shifts.png` — *Module 5: Baseline vs. Contextual Risk Validation Table and Rank Shift Chart.*
- `docs/screenshots/06_audit_report.png` — *Module 6: Automated Markdown Security Audit Report Generator.*
