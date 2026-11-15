# Course Project Report Outline (`docs/report_outline.md`)

**Course:** Security Risk Management Principles (`21CSC308T`)  
**Project Title:** RiskSIEM — Business-Risk-Scored SIEM & Tamper-Evident Audit Layer for Greenfield Institute of Technology

---

## 1. Course Outcome (CO) Mapping Table (To Be Completed by Student)

| Course Outcome | Statement | Project Module / Deliverable Mapped | Student Notes / Evidence Reference |
|---|---|---|---|
| **CO-1** | *[Insert CO-1 description from syllabus]* | | |
| **CO-2** | *[Insert CO-2 description from syllabus]* | | |
| **CO-3** | *[Insert CO-3 description from syllabus]* | | |
| **CO-4** | *[Insert CO-4 description from syllabus]* | | |
| **CO-5** | *[Insert CO-5 description from syllabus]* | | |

---

## 2. Report Chapter Outline Mapped to Course Units

### Chapter 1: Introduction & Problem Statement
- **1.1 Motivation:** Why traditional SIEM alert queues sorted only by static severity or event volume cause alert fatigue and misprioritize business-critical assets.
- **1.2 Project Objectives:** Building a local, deterministic risk and audit layer (`RiskSIEM`) covering business-risk scoring, automated audit evidence & control testing, and tamper-evident log storage.

### Chapter 2: Data Collection & Asset Scoping (Mapped to Course Unit 2)
- **2.1 Subject Organisation Profile:** Greenfield Institute of Technology (GIT) architecture and IT operational context.
- **2.2 Asset Inventory & Valuation (`data/assets.csv`):** Scoping the six core assets (`A1` Student Records DB, `A2` Payroll Server, `A3` Student Web Portal, `A4` Lab Workstation, `A5` Online Exam Server, `A6` Guest Wi-Fi Gateway) and assigning business criticality values (1–5).
- **2.3 Log Data Sources (`engine/parse.py`, `scripts/generate_logs.py`):** Structured ingestion of OpenSSH (`sshd`), `sudo`, Linux `UFW` firewall, and `pam_tally2` authentication telemetry.

### Chapter 3: Threat, Vulnerability & Risk Assessment Methodology (Mapped to Course Unit 3)
- **3.1 Confidentiality, Integrity, and Availability (CIA) Requirements:** Assigning C, I, A ratings (1–5) per asset.
- **3.2 Threat Catalog (`data/threats.csv`):** MITRE ATT&CK techniques `T1110` (Brute Force), `T1046` (Port Scanning), and `T1548` (Privilege Escalation), base likelihoods, and primary CIA dimensions harmed.
- **3.3 Vulnerability Catalog (`data/vulnerabilities.csv`) & Threat–Vulnerability (TV) Pairs (`data/tv_pairs.csv`):** Mapping `T1110 -> (V1, V2)`, `T1046 -> V3`, and `T1548 -> V4`.
- **3.4 Asset Exposure Matrix (`data/exposure.csv`) & Quantitative Risk Formula (`engine/risk.py`):** Step-by-step derivation of Impact ($I$), Frequency Bonus ($F$), Likelihood ($L$), and Risk ($R = L \times I$), plus residual risk calculation after treatment.

### Chapter 4: Security Control Mapping, Testing & Issues Register (Mapped to Course Unit 4)
- **4.1 Control Framework Alignment (`data/control_map.csv`):** Mapping detections to **NIST SP 800-53 Rev. 5** (`AC-7`, `SC-7`, `AC-6`, `AU-9`) and **CIS Critical Security Controls v8** (`CIS 5`, `CIS 13`, `CIS 6`, `CIS 8`).
- **4.2 Automated Control Testing (`engine/evidence.py`):** Evaluating account lockout presence within 120s (`AC-7`), boundary scan containment/rate-limiting (`SC-7`), and least-privilege sudo enforcement (`AC-6`).
- **4.3 Issues Register Generation & Recommended Treatments (`data/treatments.csv`):** Lifecycle of an open audit issue and treatment prioritization.

### Chapter 5: Audit Evidence Types, Log Integrity & Audit Reporting (Mapped to Course Unit 5)
- **5.1 Direct vs. Indirect Audit Evidence:** Distinguishing primary raw log records (with SHA-256 chain hashes) from secondary analytical conclusions (sliding-window correlation and risk score records).
- **5.2 Tamper-Evident SHA-256 Log Chain & External Anchoring (`engine/chain.py`):** Protecting audit information under **NIST AU-9 / CIS 8**; detecting record modification (`tamper_demo.py`), deletion, reordering, and truncation.
- **5.3 Validation Results (Baseline vs. Risk Ranking):** Empirical analysis of rank shifts across Scenarios `S1`–`S6` (highlighting why `S4` Payroll brute force outranks `S3` Guest Wi-Fi brute force).
- **5.4 Automated Markdown Audit Report & Limitations (`docs/limitations.md`):** Summary of generated audit report and architectural trade-offs.
