# Known Limitations (`docs/limitations.md`)

## 1. Synthetic Log Telemetry
The log files (`data/sample/auth.log` and `data/sample/auth_with_lockout.log`) are synthetically generated using `scripts/generate_logs.py` (seeded with `random.seed(42)`). While they faithfully model standard OpenSSH, `sudo`, UFW kernel, and `pam_tally2` syslog formats, they do not contain the messy formatting variations, clock skew, multiline stack traces, or high-volume background noise of a live campus network.

## 2. Subjectivity of Assessor-Assigned Ratings
All asset criticality values (`value`), CIA requirement ratings (`C`, `I`, `A`), threat `base_likelihood` values, and per-asset vulnerability `exposure` scores on the 1–5 scale are assigned by the risk assessor based on the fictional Greenfield Institute of Technology profile. Different assessors might assign slightly different integer ratings, which could alter intermediate scores or tie-breaks.

## 3. Hash Chain Local Anchoring Limitation (NIST AU-9)
RiskSIEM chains every row in `log_events` using SHA-256 and writes the final chain head hash and row count to `anchor/head.txt` (and `anchor/head_history.log`).
- **What this catches:** Any direct edit, deletion, reordering, or truncation inside `riskSIEM.db` is immediately detected by `verify_chain()`, including a full database rewrite if the attacker does not also update `anchor/head.txt`.
- **What this cannot prevent:** An attacker who compromises the local host with write permissions to **both** `riskSIEM.db` and the local `anchor/` directory could modify a log line, recompute all subsequent SHA-256 hashes, and overwrite `anchor/head.txt` to match.
- **Production Mitigation:** In a real deployment, the anchor file must be transmitted to a separate, write-protected/WORM (Write-Once-Read-Many) host, hardware security module (HSM), or append-only external transparency log.

## 4. Scope Limited to Three Detection Rules
Detection coverage (`engine/detect.py`) is intentionally scoped to three core rules:
- **R1 (`T1110`):** SSH brute-force bursts ($\ge 5$ failures within 120 seconds). Low-and-slow password spraying distributed across multiple source IPs or longer intervals (>120s) will not trigger R1.
- **R2 (`T1046`):** Firewall port scans ($\ge 10$ distinct ports within 60 seconds). Slow reconnaissance probing fewer than 10 ports per minute will not trigger R2.
- **R3 (`T1548`):** Non-admin `sudo` elevation to `root`. Privilege escalation via kernel exploits, SUID binaries, or compromised `admin`/`sysadmin` credentials is not covered by R3.

## 5. Absence of Empirical False-Positive / False-Negative Evaluation
Because the evaluation runs on a deterministic synthetic corpus rather than labeled production traffic, precision, recall, false-positive rate (FPR), and false-negative rate (FNR) on real enterprise traffic have not been empirically benchmarked.

## 6. Requirements for a Real Production Deployment
Transitioning RiskSIEM from a university lab prototype to production would require:
1. Streaming syslog ingestion (`rsyslog` / `syslog-ng` over TLS) into an append-only database with role-based access control.
2. Remote WORM anchoring or cryptographic timestamping (RFC 3161) on an isolated audit server.
3. Automated asset discovery and vulnerability scanner integration (e.g., OpenVAS / Nessus CVE feeds) to populate `exposure.csv` dynamically.
4. Broadened rule coverage (MITRE ATT&CK lateral movement, persistence, exfiltration) and baseline anomaly detection.
