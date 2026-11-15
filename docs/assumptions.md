# Assumptions & Design Choices (`docs/assumptions.md`)

Where the build specification left minor implementation details open, the simplest deterministic option was chosen and documented below:

1. **Synthetic Log Line Count & `tamper_demo.py` Default ID (`id = 150`):**
   - Section 7 specifies that `scripts/tamper_demo.py` defaults to modifying `id = 150` and replacing a source IP.
   - To guarantee that `id = 150` always exists in `log_events` and contains a valid IPv4 address, `scripts/generate_logs.py` generates **157 total lines** in `data/sample/auth.log`: 84 lines across scenarios `S1`–`S6`, 30 normal `Accepted password` logins across all six hosts, 4 allowed `sudo` commands by `admin`/`sysadmin`, 3 isolated failed login bursts on `web-srv-01` (3 attempts each, $<5$ per 2 minutes), and 5 isolated firewall block bursts (6 distinct ports each, $<10$ distinct ports per minute).
   - None of the 73 benign noise lines trigger `R1`, `R2`, or `R3`, and record `id = 150` is a log line with a source IP (`192.0.2.15`), allowing `python scripts/tamper_demo.py` to work with zero arguments out of the box.

2. **Extra Lockout Scenario File (`data/sample/auth_with_lockout.log`):**
   - Section 4.3, Section 11, and Section 13 specify that `auth_with_lockout.log` should demonstrate a brute-force burst followed by a `pam_tally2` lockout line within 120 seconds so that the **AC-7** control test passes and raises **0 issues**.
   - `auth_with_lockout.log` contains a 12-event SSH brute-force burst against `pay-srv-01` (`09:15:02` to `09:15:57`) followed 33 seconds later (`09:16:30`) by `pam_tally2[1300]: user root locked out after too many failures`, plus benign admin activity. Running the pipeline on this file yields 1 brute-force detection (`T1110`) and **0 issues** in the issues register.

3. **Detection Ordering and Scenario Mapping (`S1`–`S6`):**
   - Detections in `engine/detect.py` are sorted chronologically by `first_seen` ascending (then `threat_id`, then `host`) and assigned sequential `detection_id` values `1` through `6`. Because scenarios `S1` through `S6` occur at `08:40`, `08:55`, `09:00`, `09:10`, `09:18`, and `09:25` respectively, `detection_id` `1..6` maps 1-to-1 with `S1..S6`.

4. **Port Parsing on SSH Events (`dst_port`):**
   - In `engine/parse.py`, for `sshd` lines (`Failed password ... port 51234 ssh2` and `Accepted password ... port 40022 ssh2`), the port integer is stored in `dst_port`, while for `[UFW BLOCK] ... DPT=22`, the destination port `DPT` is stored in `dst_port`. Detection rule `R2` filters strictly on `event_type == 'fw_block'`.

5. **Dashboard Aesthetic & Stretch Feature ("Treat Risk"):**
   - The Streamlit dashboard (`dashboard/app.py`) implements the Dark SOC executive template aesthetic while remaining 100% local and Streamlit-native.
   - The Stretch Feature ("Treat Risk") is implemented on the Overview page: selecting any detection(s) (or clicking **Treat All Risks**) reduces `exposure[A][T]` by 2 (clamped to minimum 1), recomputes residual Likelihood ($L_{\text{res}}$), Residual Risk ($R_{\text{res}}$), and Residual Band, and displays them alongside the original risk score.
