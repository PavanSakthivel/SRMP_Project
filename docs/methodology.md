# RiskSIEM Methodology (`docs/methodology.md`)

## 1. Fictional Organisation Profile

**Greenfield Institute of Technology (GIT)** is a mid-sized college operating six core infrastructure assets managed by a lean central IT Services team. Because security analyst time is constrained, alerts generated from raw system logs must be prioritized by **institutional business risk** rather than raw event count or uncontextualized rule severity.

> **Important Statement on Input Provenance:** All asset business values (`value`), Confidentiality/Integrity/Availability (`C`, `I`, `A`) requirement ratings, threat base likelihoods (`base_likelihood`), and per-asset vulnerability exposure scores (`exposure[A][T]`) are **assessor-assigned qualitative/semi-quantitative ratings** derived from the fictional Greenfield Institute of Technology profile. They are structured **assumptions**, not empirically measured probabilities.

---

## 2. Reference Inputs and Sources

| Input Table | File | Purpose & Source Rationale |
|---|---|---|
| **Asset Inventory** | `data/assets.csv` | Defines 6 scoped hosts (`A1`–`A6`), asset owner, business criticality `value` (1–5), and CIA requirement ratings `C`, `I`, `A` (1–5). Institutional databases (`db-srv-01`, `pay-srv-01`) carry maximum value (`5`) and Confidentiality/Integrity (`5`), whereas `ws-lab-01` (`A4`) and `gw-01` (`A6`) carry value `2`. |
| **Threat Catalog** | `data/threats.csv` | Maps three MITRE ATT&CK techniques (`T1110` Brute Force, `T1046` Network Service Scanning, `T1548` Privilege Escalation) to `base_likelihood` (1–5), `primary_dimension` (`C` or `I`), and static `default_severity` (1–5). |
| **Vulnerability Catalog** | `data/vulnerabilities.csv` | Lists four configuration weaknesses (`V1` SSH password auth enabled, `V2` No account lockout policy, `V3` Unnecessary exposed network ports, `V4` Over-permissive sudo configuration). |
| **Threat–Vulnerability Pairs** | `data/tv_pairs.csv` | Pairs each threat with the underlying vulnerability it exploits (`T1110 -> V1, V2`, `T1046 -> V3`, `T1548 -> V4`). |
| **Vulnerability Exposure** | `data/exposure.csv` | Assessor-assigned rating (1–5) of how reachable or vulnerable each asset `A` is to each threat `T`. |
| **Control Mapping** | `data/control_map.csv` | Links each threat to **NIST SP 800-53 Rev. 5** and **CIS Controls v8** (`T1110 -> AC-7 / CIS 5`, `T1046 -> SC-7 / CIS 13`, `T1548 -> AC-6 / CIS 6`), plus universal log integrity mapping (`AU-9 / CIS 8`). |
| **Recommended Treatments** | `data/treatments.csv` | Defines concrete remediation actions per threat to reduce exposure. |

---

## 3. Exact Risk Scoring Formulas

Define deterministic rounding helper:
$$\text{round\_half\_up}(x) = \lfloor x + 0.5 \rfloor$$

For a detection of threat $T$ with event count $n$ on asset $A$:

1. **Impact ($I$):**
   $$I = \text{clamp}\left(\text{round\_half\_up}\left(\frac{A.\text{value} + A.\text{rating}[T.\text{primary\_dimension}]}{2}\right), 1, 5\right)$$

2. **Frequency Bonus ($F$):**
   - **T1110 (failed SSH attempts $n$):**
     - $n < 20 \implies F = 0$
     - $20 \le n \le 39 \implies F = 0.5$
     - $n \ge 40 \implies F = 1.0$
   - **T1046 (distinct scanned ports $n$):**
     - $n < 25 \implies F = 0$
     - $25 \le n \le 49 \implies F = 0.5$
     - $n \ge 50 \implies F = 1.0$
   - **T1548 (privilege escalation):** always $F = 0$.

3. **Likelihood ($L$):**
   $$L = \min\left(5, \max\left(1, \text{round\_half\_up}\left(\frac{T.\text{base\_likelihood} + \text{exposure}[A][T]}{2} + F\right)\right)\right)$$

4. **Risk Score ($R$):**
   $$R = L \times I \quad (\text{range } 1\text{–}25)$$

5. **Risk Band:**
   - **20–25:** `Critical`
   - **12–19:** `High`
   - **6–11:** `Medium`
   - **1–5:** `Low`

6. **Ranking Rules:**
   - **Baseline (Plain-Severity) Ranking:** Sort by `default_severity` DESC, then `event_count` DESC, then `first_seen` ASC.
   - **Contextual Risk Ranking:** Sort by `R` DESC, then `I` DESC, then `default_severity` DESC, then `first_seen` ASC.
   - **Priority Shift:** $\text{Shift} = \text{baseline\_rank} - \text{risk\_rank}$ (positive values mean the alert moved **up** in priority).

---

## 4. Complete Worked Example (S4 vs. S3)

### Scenario S4: Payroll Server Brute Force (`pay-srv-01`, Asset `A2`, Threat `T1110`, $n = 12$)
1. **Inputs:** $A2.\text{value} = 5$, $T1110.\text{primary\_dimension} = C$, $A2.C = 5$, $T1110.\text{base\_likelihood} = 4$, $\text{exposure}[A2][T1110] = 4$, $n = 12$.
2. **Impact ($I$):** $\text{round\_half\_up}((5 + 5)/2) = \text{round\_half\_up}(5.0) = 5$.
3. **Frequency Bonus ($F$):** Since $n = 12 < 20$, $F = 0$.
4. **Likelihood ($L$):** $\text{round\_half\_up}((4 + 4)/2 + 0) = 4$.
5. **Risk Score ($R$):** $4 \times 5 = \mathbf{20}$ (**Critical**).

### Scenario S3: Guest Wi-Fi Gateway Brute Force (`gw-01`, Asset `A6`, Threat `T1110`, $n = 40$)
1. **Inputs:** $A6.\text{value} = 2$, $T1110.\text{primary\_dimension} = C$, $A6.C = 1$, $T1110.\text{base\_likelihood} = 4$, $\text{exposure}[A6][T1110] = 5$, $n = 40$.
2. **Impact ($I$):** $\text{round\_half\_up}((2 + 1)/2) = \text{round\_half\_up}(1.5) = 2$.
3. **Frequency Bonus ($F$):** Since $n = 40 \ge 40$, $F = 1.0$.
4. **Likelihood ($L$):** $\min(5, \text{round\_half\_up}((4 + 5)/2 + 1.0)) = \min(5, \text{round\_half\_up}(5.5)) = 5$.
5. **Risk Score ($R$):** $5 \times 2 = \mathbf{10}$ (**Medium**).

**Conclusion:** Even though `S3` has more than $3\times$ the login failures of `S4` (putting `S3` at Rank 3 ahead of `S4` at Rank 4 under baseline ranking), RiskSIEM elevates `S4` to **Rank 2 (Critical, 20)** and demotes `S3` to **Rank 5 (Medium, 10)**.

---

## 5. Direct vs. Indirect Audit Evidence & Control Mapping Rationale

- **Direct Evidence (`type = 'direct'`):** Unaltered primary system records—specifically each raw syslog line that triggered a detection, linked to its `log_event_id` and its cryptographic SHA-256 chain hash (`hash`). Direct evidence proves that the underlying technical events occurred on the host without analyst interpretation.
- **Indirect Evidence (`type = 'indirect'`):** Derived analytical artifacts produced by the SIEM engine—specifically (a) the window correlation conclusion (e.g., *"12 failed logins from IP 198.51.100.23 to pay-srv-01 within 55 seconds"*) and (b) the computed risk score record ($L$, $I$, $F$, $R$, band, and rank). Indirect evidence supports the auditor's assessment of severity and control effectiveness.
- **Control Mapping Rationale:**
  - **T1110 $\rightarrow$ NIST AC-7 (Unsuccessful Logon Attempts) / CIS Control 5:** Requires automated account lockout after a threshold of consecutive failed logins. Evaluated by checking whether a `pam_tally2` lockout log line occurs on the same host within 120 seconds after the failure burst ends.
  - **T1046 $\rightarrow$ NIST SC-7 (Boundary Protection) / CIS Control 13:** Requires perimeter filtering and scan rate-limiting. When 10+ distinct ports are probed within 60 seconds, the scan was visible across the boundary without rate-limiting; marked as failed while noting that `[UFW BLOCK]` contained packet delivery.
  - **T1548 $\rightarrow$ NIST AC-6 (Least Privilege) / CIS Control 6:** Requires restricting root privilege elevation exclusively to authorized administrative accounts (`admin`, `sysadmin`). Any `sudo ... USER=root` invocation by another account immediately fails the control test.
  - **All Logs $\rightarrow$ NIST AU-9 (Protection of Audit Information) / CIS Control 8:** Enforced via the SHA-256 hash chain and external head anchor.
