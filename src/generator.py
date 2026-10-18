"""Step 2 - Generate realistic sample logs (Linux auth.log + Windows events) with injected attacks."""
import csv
import io
import random
from datetime import datetime, timedelta
from pathlib import Path

USERS = ["alice", "bob", "carol", "dave", "sergio"]
NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "10.0.0.5"]
BASE = datetime(2026, 9, 28, 8, 0, 0)


def _ssh_line(ts, host, event, user, ip):
    t = ts.strftime("%b %d %H:%M:%S")
    pid = random.randint(1000, 9999)
    port = random.randint(30000, 60000)
    if event == "fail":
        return f"{t} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"
    if event == "invalid":
        return f"{t} {host} sshd[{pid}]: Invalid user {user} from {ip} port {port}"
    return f"{t} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"


def generate_linux_log(seed=42):
    """Returns (lines, ground_truth). Ground truth lists the attacks hidden in the log."""
    random.seed(seed)
    host, lines = "web-server-01", []
    for _ in range(120):  # normal working-hours traffic
        ts = BASE + timedelta(minutes=random.randint(0, 600))
        ev = "ok" if random.random() > 0.08 else "fail"
        lines.append((ts, _ssh_line(ts, host, ev, random.choice(USERS), random.choice(NORMAL_IPS))))
    # ATTACK 1: brute force on root, then success
    t0 = BASE + timedelta(hours=2)
    for i in range(35):
        ts = t0 + timedelta(seconds=i * 6)
        lines.append((ts, _ssh_line(ts, host, "fail", "root", "203.0.113.50")))
    ts = t0 + timedelta(seconds=230)
    lines.append((ts, _ssh_line(ts, host, "ok", "root", "203.0.113.50")))
    # ATTACK 2: password spraying
    t1 = BASE + timedelta(hours=5)
    for i, u in enumerate(["admin", "test", "oracle", "ubuntu", "postgres", "alice", "bob", "carol"]):
        ts = t1 + timedelta(seconds=i * 20)
        lines.append((ts, _ssh_line(ts, host, "fail", u, "198.51.100.7")))
    # ATTACK 3: invalid user probing
    t2 = BASE + timedelta(hours=7)
    for i, u in enumerate(["guest", "pi", "ftpuser", "git", "jenkins", "hadoop"]):
        ts = t2 + timedelta(seconds=i * 15)
        lines.append((ts, _ssh_line(ts, host, "invalid", u, "192.0.2.99")))
    # ATTACK 4: odd-hour login (3 AM)
    ts = datetime(2026, 9, 29, 3, 12, 0)
    lines.append((ts, _ssh_line(ts, host, "ok", "dave", "45.33.32.156")))
    lines.sort(key=lambda x: x[0])
    truth = {
        "brute_force": "203.0.113.50", "success_after_failures": "203.0.113.50",
        "password_spraying": "198.51.100.7", "invalid_user_probing": "192.0.2.99",
        "odd_hour_login": "45.33.32.156",
    }
    return [l for _, l in lines], truth


WIN_HEADER = "timestamp,host,event_id,user,ip,target_user,group,command_line"
BENIGN_PROCESSES = [
    r"C:\Windows\System32\svchost.exe -k netsvcs",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"powershell.exe -File C:\Scripts\backup.ps1",
    r"powershell.exe Get-Service",
    r"C:\Windows\System32\notepad.exe",
]


def _win_row(ts, host, eid, user, ip, target="", group="", cmd=""):
    buf = io.StringIO()
    csv.writer(buf, lineterminator="").writerow([f"{ts:%Y-%m-%d %H:%M:%S}", host, eid, user, ip, target, group, cmd])
    return ts, buf.getvalue()


def generate_windows_log(seed=7):
    """CSV-style Windows Security events (see WIN_HEADER) with a full attack chain hidden in normal activity."""
    random.seed(seed)
    host, rows = "WIN-DC01", []
    for _ in range(60):  # normal logons
        ts = BASE + timedelta(minutes=random.randint(0, 600))
        eid = 4624 if random.random() > 0.1 else 4625
        rows.append(_win_row(ts, host, eid, random.choice(USERS), random.choice(NORMAL_IPS)))
    for _ in range(20):  # normal process starts, incl. harmless PowerShell that must NOT alert
        ts = BASE + timedelta(minutes=random.randint(0, 600))
        rows.append(_win_row(ts, host, 4688, random.choice(USERS), random.choice(NORMAL_IPS),
                             cmd=random.choice(BENIGN_PROCESSES)))
    # benign: helpdesk adds a user to a non-privileged group (must NOT alert)
    rows.append(_win_row(BASE + timedelta(hours=1), host, 4732, "helpdesk", "192.168.1.10", "carol", "Print Operators"))

    # ATTACK CHAIN from 185.220.101.4: RDP brute force -> lockout -> break-in -> persistence -> execution -> cover-up
    ip, t0 = "185.220.101.4", BASE + timedelta(hours=4)
    for i in range(25):
        rows.append(_win_row(t0 + timedelta(seconds=i * 8), host, 4625, "administrator", ip))
    rows.append(_win_row(t0 + timedelta(seconds=205), host, 4740, "administrator", ip, target="administrator"))
    rows.append(_win_row(t0 + timedelta(seconds=260), host, 4624, "administrator", ip))
    rows.append(_win_row(t0 + timedelta(minutes=6), host, 4720, "administrator", ip, target="svc_update"))
    rows.append(_win_row(t0 + timedelta(minutes=7), host, 4732, "administrator", ip, "svc_update", "Administrators"))
    rows.append(_win_row(t0 + timedelta(minutes=9), host, 4688, "administrator", ip,
                         cmd="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="))
    rows.append(_win_row(t0 + timedelta(minutes=12), host, 1102, "administrator", ip))
    rows.sort(key=lambda x: x[0])
    truth = {"brute_force": ip, "account_lockout": ip, "success_after_failures": ip, "new_account_created": ip,
             "admin_group_add": ip, "suspicious_powershell": ip, "audit_log_cleared": ip}
    return [WIN_HEADER] + [r for _, r in rows], truth


def write_samples(out_dir="data/sample_logs"):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    lin, t1 = generate_linux_log()
    win, t2 = generate_windows_log()
    (out / "auth.log").write_text("\n".join(lin) + "\n")
    (out / "windows_security.csv").write_text("\n".join(win) + "\n")
    return {"linux": t1, "windows": t2}


if __name__ == "__main__":
    print(write_samples())
