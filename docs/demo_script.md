# 5-Minute Live Grading Demo Script (`docs/demo_script.md`)

## Pre-Demo Preparation (30 seconds before presenting)
Open two terminals in the `risksiem/` folder:
- **Terminal 1 (Pipeline & Tamper CLI):** Ready to run `python scripts/run_pipeline.py` and `python scripts/tamper_demo.py`.
- **Terminal 2 (Streamlit Server):** Run `python -m streamlit run dashboard/app.py` and keep the browser open to `http://localhost:8501`.

---

## Minute 0:00 – 0:45 | 1. Show Organisation & Methodology (Module 2)
1. In the sidebar, click **`2. Methodology & Catalogs`**.
2. Introduce **Greenfield Institute of Technology (GIT)** and point out the **Asset Inventory** (`db-srv-01` and `pay-srv-01` have business value `5`; `ws-lab-01` and `gw-01` have value `2`).
3. Scroll to **Threat–Vulnerability Pairs (`tv_pairs.csv`)** and the **Vulnerability Exposure Matrix (`exposure.csv`)**, explaining that these are assessor-assigned assumptions from the organisation profile.
4. Briefly highlight the **Scoring Formulas & Worked Example** ($I$, $F$, $L$, and $R = L \times I$).

---

## Minute 0:45 – 1:30 | 2. Run Pipeline on the Sample Log (CLI)
1. Switch to **Terminal 1** and run:
   ```bash
   python scripts/run_pipeline.py
   ```
2. Point out the terminal summary table:
   - `157 events` ingested into `riskSIEM.db` with SHA-256 chain head anchored.
   - Exactly **6 detections (`S1`–`S6`)**, **96 evidence items (84 direct, 12 indirect)**, and **6 open issues**.

---

## Minute 1:30 – 2:30 | 3. Show Risk-Ranked Alerts & Residual Risk (Module 1)
1. Switch back to the browser and select **`1. Overview & Risk Matrix`**.
2. Point out the **4 KPI Cards** (6 Detections, 2 Critical Alerts on `db-srv-01` and `pay-srv-01`, 2 High / 2 Medium, and green `INTACT (VALID)` SHA-256 chain status).
3. Show the **Risk-Ranked Detection Queue** and the **5×5 Likelihood vs. Impact Matrix Heatmap** on the right (`S2, S4` clustered in the top-right Critical cell `[L=4, I=5 -> Risk=20]`).
4. **Demonstrate the Stretch Feature ("Treat Risk"):** Click **`🛡️ Treat All Risks (-2 Exposure)`** (or select `S4 • pay-srv-01` in the multiselect). Show how reducing exposure by 2 drops `S2` and `S4` from **Critical (20)** to **High (15)**, then click **`↩️ Reset Treatments`**.

---

## Minute 2:30 – 3:15 | 4. Show Validation Page & Explain Rank Shifts (Module 5)
1. Click **`5. Baseline vs Validation`** in the sidebar.
2. Point to the **Golden Validation Table** and the **Priority Rank Shift Bar Chart**:
   - **Headline Finding:** Compare **S4 (`pay-srv-01` Payroll Server, 12 failed SSH attempts)** vs. **S3 (`gw-01` Guest Wi-Fi Gateway, 40 failed SSH attempts)**.
   - Under plain severity-and-volume ranking, `S3` is ranked higher (#3) than `S4` (#4) because 40 > 12.
   - Under RiskSIEM scoring, **`S4` jumps +2 ranks to #2 (Critical, Risk=20)** while **`S3` drops -2 ranks to #5 (Medium, Risk=10)** because the Payroll Server has maximum asset criticality and confidentiality ($I=5$ vs. $I=2$).
   - Also mention **S6 (`exam-srv-01` port scan)** rising **+3 ranks (Rank 6 $\rightarrow$ Rank 3)** and **S1 (`ws-lab-01` sudo)** dropping **-3 ranks (Rank 1 $\rightarrow$ Rank 4)**.

---

## Minute 3:15 – 3:55 | 5. Show Audit Evidence & Issues Register (Module 3)
1. Click **`3. Audit Evidence & Issues`** in the sidebar.
2. Show the **Issues Register** containing the 6 open control failures (`AC-7`, `SC-7`, `AC-6`) and click **Download Issues Register (`issues.csv`)**.
3. Filter the **Audit Evidence Explorer** between `direct` (84 raw log lines with SHA-256 hashes) and `indirect` (12 correlation & risk score records).
4. *(Optional 10-second bonus):* Click **`🔒 Load AC-7 Lockout Log`** in the sidebar Quick Actions to show that when a `pam_tally2` lockout line follows the brute-force burst within 120s, the Issues Register drops to **0 open issues**! Click **`🔄 Reset & Re-ingest (auth.log)`** to return to the main dataset.

---

## Minute 3:55 – 4:35 | 6. Run Tamper Demo & Verify Detection (Module 4)
1. Navigate to **`4. Tamper-Evident Log Chain`**. Show the green **`✅ CHAIN INTACT — ALL 157 LOG BLOCKS VERIFIED`** banner.
2. In **Terminal 1** (or via the **`💥 Simulate Tamper on Record #150`** button), run:
   ```bash
   python scripts/tamper_demo.py
   ```
3. Click **`🔍 Verify Integrity Now`** on the page.
4. Point to the red alert banner: **`🚨 TAMPERING DETECTED AT RECORD ID 150 — hash mismatch at id 150 (modified log record)`**, and show the inspected record #150 where the attacker altered the source IP to `192.0.2.254`.
5. Click **`♻️ Reset & Restore Clean Chain`** (or run `python scripts/reset_demo.py`) to restore the green verified state.

---

## Minute 4:35 – 5:00 | 7. Generate & Download the Audit Report (Module 6)
1. Click **`6. Audit Report Generator`** in the sidebar.
2. Scroll through the live 8-section Markdown Audit Report (Scope, Methodology, Evidence Counts, Findings Table, Validation Summary, Log Integrity Result, Treatments, and Limitations).
3. Click **`📥 Download Markdown Audit Report (risksiem_audit_report.md)`**.

---

## 8. Fallback Tips (If Live Demo Encounters Any Issue)
- **If the browser/port is busy:** Run `python scripts/run_pipeline.py` and `python -m pytest -v` directly in the terminal—the CLI prints the entire Section 11 table, evidence counts, and chain status cleanly in ASCII.
- **If the database is left in a tampered or lockout state:** Run `python scripts/reset_demo.py` to wipe `riskSIEM.db` and `anchor/` and regenerate the clean baseline in under 1 second.
- **Pre-generated artifacts:** Keep a downloaded copy of `risksiem_audit_report.md`, `issues.csv`, and `evidence.csv` ready in your presentation folder as backup exhibits.
