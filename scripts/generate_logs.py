"""Generate deterministic synthetic log files for RiskSIEM."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import random

ROOT_DIR = Path(__file__).resolve().parent.parent
SAMPLE_DIR = ROOT_DIR / "data" / "sample"

IST = timezone(timedelta(hours=5, minutes=30))

HOSTS = [
    ("db-srv-01", "10.0.0.1"),
    ("pay-srv-01", "10.0.0.2"),
    ("web-srv-01", "10.0.0.3"),
    ("ws-lab-01", "10.0.0.4"),
    ("exam-srv-01", "10.0.0.5"),
    ("gw-01", "10.0.0.6"),
]

SCAN_PORTS_15 = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080]


def fmt_ts(dt: datetime) -> str:
    """Format a datetime as ISO-8601 with +05:30 offset (seconds precision)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S+05:30")


def generate_main_log(rng: random.Random) -> list[str]:
    """Generate the main sample log (auth.log) containing S1-S6 and benign noise."""
    entries: list[tuple[datetime, int, str]] = []
    seq = 0

    def add(dt: datetime, line: str) -> None:
        nonlocal seq
        seq += 1
        entries.append((dt, seq, line))

    base = datetime(2026, 11, 10, 8, 0, 0, tzinfo=IST)

    # --- Scenarios S1 to S6 ---

    # S1: ws-lab-01 at 2026-11-10T08:40 - carol (non-admin) runs sudo USER=root once
    s1_dt = datetime(2026, 11, 10, 8, 40, 12, tzinfo=IST)
    add(
        s1_dt,
        f"{fmt_ts(s1_dt)} ws-lab-01 sudo: carol : TTY=pts/0 ; PWD=/home/carol ; USER=root ; COMMAND=/bin/bash",
    )

    # S2: db-srv-01 at 2026-11-10T08:55 - bob (non-admin) runs sudo USER=root once
    s2_dt = datetime(2026, 11, 10, 8, 55, 18, tzinfo=IST)
    add(
        s2_dt,
        f"{fmt_ts(s2_dt)} db-srv-01 sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash",
    )

    # S3: gw-01 at 2026-11-10T09:00 - 40 failed SSH logins from 203.0.113.45 within 90s
    s3_start = datetime(2026, 11, 10, 9, 0, 0, tzinfo=IST)
    s3_users = ["admin", "root", "ubuntu", "test", "guest"]
    for i in range(40):
        dt = s3_start + timedelta(seconds=i * 2)  # 0 to 78 seconds (<= 90s)
        user = s3_users[i % len(s3_users)]
        port = 51000 + i
        if user in ("admin", "ubuntu", "test", "guest"):
            msg = f"Failed password for invalid user {user} from 203.0.113.45 port {port} ssh2"
        else:
            msg = f"Failed password for root from 203.0.113.45 port {port} ssh2"
        add(dt, f"{fmt_ts(dt)} gw-01 sshd[2100]: {msg}")

    # S4: pay-srv-01 at 2026-11-10T09:10 - 12 failed SSH logins from 198.51.100.23 within 90s
    s4_start = datetime(2026, 11, 10, 9, 10, 0, tzinfo=IST)
    for i in range(12):
        dt = s4_start + timedelta(seconds=i * 5)  # 0 to 55 seconds (<= 90s)
        port = 52000 + i
        if i % 2 == 0:
            msg = f"Failed password for invalid user admin from 198.51.100.23 port {port} ssh2"
        else:
            msg = f"Failed password for root from 198.51.100.23 port {port} ssh2"
        add(dt, f"{fmt_ts(dt)} pay-srv-01 sshd[1234]: {msg}")

    # S5: gw-01 at 2026-11-10T09:18 - 15 firewall blocks from 198.51.100.7 to 15 distinct ports within 40s
    s5_start = datetime(2026, 11, 10, 9, 18, 0, tzinfo=IST)
    for i, dpt in enumerate(SCAN_PORTS_15):
        dt = s5_start + timedelta(seconds=i * 2)  # 0 to 28 seconds (<= 40s)
        add(
            dt,
            f"{fmt_ts(dt)} gw-01 kernel: [UFW BLOCK] SRC=198.51.100.7 DST=10.0.0.6 PROTO=TCP DPT={dpt}",
        )

    # S6: exam-srv-01 at 2026-11-10T09:25 - 15 firewall blocks from 198.51.100.8 to 15 distinct ports within 40s
    s6_start = datetime(2026, 11, 10, 9, 25, 0, tzinfo=IST)
    for i, dpt in enumerate(SCAN_PORTS_15):
        dt = s6_start + timedelta(seconds=i * 2)  # 0 to 28 seconds (<= 40s)
        add(
            dt,
            f"{fmt_ts(dt)} exam-srv-01 kernel: [UFW BLOCK] SRC=198.51.100.8 DST=10.0.0.5 PROTO=TCP DPT={dpt}",
        )

    # --- Benign Noise (must NOT trigger detections) ---

    # 1) 30 normal Accepted password logins by admin and sysadmin across all 6 hosts
    admins = ["admin", "sysadmin"]
    for i in range(30):
        host, _ = HOSTS[i % len(HOSTS)]
        user = admins[i % len(admins)]
        src_ip = f"10.0.0.{10 + (i % 15)}"
        port = 40000 + rng.randint(10, 999)
        dt = base + timedelta(minutes=i * 4, seconds=rng.randint(1, 45))
        add(
            dt,
            f"{fmt_ts(dt)} {host} sshd[{3000 + i}]: Accepted password for {user} from {src_ip} port {port} ssh2",
        )

    # 2) 3 isolated failed login bursts (3 attempts each < 5 per 2 minutes) on web-srv-01
    isolated_fail_times = [
        datetime(2026, 11, 10, 8, 12, 10, tzinfo=IST),
        datetime(2026, 11, 10, 9, 35, 20, tzinfo=IST),
        datetime(2026, 11, 10, 10, 15, 5, tzinfo=IST),
    ]
    for grp_idx, grp_dt in enumerate(isolated_fail_times):
        for j in range(3):
            dt = grp_dt + timedelta(seconds=j * 15)
            port = 53000 + grp_idx * 10 + j
            add(
                dt,
                f"{fmt_ts(dt)} web-srv-01 sshd[4100]: Failed password for invalid user admin from 192.0.2.15 port {port} ssh2",
            )

    # 3) 4 sudo root commands by admin and sysadmin (allowed)
    allowed_sudo_specs = [
        (datetime(2026, 11, 10, 8, 20, 5, tzinfo=IST), "db-srv-01", "admin", "/usr/bin/systemctl status postgresql"),
        (datetime(2026, 11, 10, 8, 48, 30, tzinfo=IST), "pay-srv-01", "sysadmin", "/usr/bin/apt update"),
        (datetime(2026, 11, 10, 9, 42, 10, tzinfo=IST), "web-srv-01", "admin", "/usr/sbin/nginx -t"),
        (datetime(2026, 11, 10, 10, 5, 33, tzinfo=IST), "exam-srv-01", "sysadmin", "/bin/ls /root"),
    ]
    for dt, host, user, cmd in allowed_sudo_specs:
        add(
            dt,
            f"{fmt_ts(dt)} {host} sudo: {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}",
        )

    # 4) 5 isolated firewall block bursts (6 distinct ports each, fewer than 10 per minute)
    isolated_fw_specs = [
        (datetime(2026, 11, 10, 8, 25, 0, tzinfo=IST), "web-srv-01", "10.0.0.3", "192.0.2.40"),
        (datetime(2026, 11, 10, 8, 50, 0, tzinfo=IST), "db-srv-01", "10.0.0.1", "192.0.2.41"),
        (datetime(2026, 11, 10, 9, 50, 0, tzinfo=IST), "pay-srv-01", "10.0.0.2", "192.0.2.42"),
        (datetime(2026, 11, 10, 10, 10, 0, tzinfo=IST), "ws-lab-01", "10.0.0.4", "192.0.2.43"),
        (datetime(2026, 11, 10, 10, 30, 0, tzinfo=IST), "web-srv-01", "10.0.0.3", "192.0.2.44"),
    ]
    small_ports = [80, 443, 8080, 8443, 22, 3306]
    for base_dt, host, dst_ip, src_ip in isolated_fw_specs:
        for j, dpt in enumerate(small_ports):
            dt = base_dt + timedelta(seconds=j * 4)
            add(
                dt,
                f"{fmt_ts(dt)} {host} kernel: [UFW BLOCK] SRC={src_ip} DST={dst_ip} PROTO=TCP DPT={dpt}",
            )

    entries.sort(key=lambda item: (item[0], item[1]))
    return [line for _, _, line in entries]


def generate_lockout_log() -> list[str]:
    """Generate auth_with_lockout.log demonstrating a passing AC-7 control."""
    entries: list[tuple[datetime, int, str]] = []
    seq = 0

    def add(dt: datetime, line: str) -> None:
        nonlocal seq
        seq += 1
        entries.append((dt, seq, line))

    # Normal login before
    dt0 = datetime(2026, 11, 10, 9, 12, 0, tzinfo=IST)
    add(
        dt0,
        f"{fmt_ts(dt0)} db-srv-01 sshd[2201]: Accepted password for admin from 10.0.0.15 port 40022 ssh2",
    )

    # Brute force burst of 12 failed logins on pay-srv-01 from 203.0.113.45
    burst_start = datetime(2026, 11, 10, 9, 15, 2, tzinfo=IST)
    for i in range(12):
        dt = burst_start + timedelta(seconds=i * 5)  # ends at 09:15:57
        port = 51234 + i
        if i % 2 == 0:
            msg = f"Failed password for invalid user admin from 203.0.113.45 port {port} ssh2"
        else:
            msg = f"Failed password for root from 203.0.113.45 port {port} ssh2"
        add(dt, f"{fmt_ts(dt)} pay-srv-01 sshd[1234]: {msg}")

    # Lockout line within 120s after burst ends (09:16:30 is 33s after 09:15:57)
    lock_dt = datetime(2026, 11, 10, 9, 16, 30, tzinfo=IST)
    add(
        lock_dt,
        f"{fmt_ts(lock_dt)} pay-srv-01 pam_tally2[1300]: user root locked out after too many failures",
    )

    # Allowed sudo by admin
    dt_after = datetime(2026, 11, 10, 9, 20, 10, tzinfo=IST)
    add(
        dt_after,
        f"{fmt_ts(dt_after)} pay-srv-01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash",
    )

    entries.sort(key=lambda item: (item[0], item[1]))
    return [line for _, _, line in entries]


def main() -> None:
    rng = random.Random(42)
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    main_lines = generate_main_log(rng)
    auth_log_path = SAMPLE_DIR / "auth.log"
    auth_log_path.write_text("\n".join(main_lines) + "\n", encoding="utf-8")

    lockout_lines = generate_lockout_log()
    lockout_log_path = SAMPLE_DIR / "auth_with_lockout.log"
    lockout_log_path.write_text("\n".join(lockout_lines) + "\n", encoding="utf-8")

    print(f"Generated {len(main_lines)} lines -> {auth_log_path}")
    print(f"Generated {len(lockout_lines)} lines -> {lockout_log_path}")


if __name__ == "__main__":
    main()
