"""Step 3 - Parse Linux auth.log and Windows security CSV into ONE common schema.

Windows CSV columns: timestamp,host,event_id,user,ip[,target_user,group,command_line]
(the last three are optional, so older 5-column files still parse)."""
import re
from datetime import datetime
from io import StringIO
import pandas as pd

COLUMNS = ["timestamp", "host", "user", "source_ip", "event_type", "status", "source_log", "target_user", "detail"]

SSH_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s(?P<host>\S+)\ssshd\[\d+\]:\s"
    r"(?P<msg>Failed password for (?:invalid user )?(?P<u1>\S+)|Accepted \w+ for (?P<u2>\S+)|Invalid user (?P<u3>\S*))"
    r".*?from\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# Key-only SSH servers log brute force as "Too many authentication failures" WITHOUT the source IP;
# the IP is recovered from another line written by the same sshd process (same PID, a few lines away),
# which works when sshd runs with LogLevel VERBOSE. Otherwise the source is recorded as 'unknown'.
SSH_TOO_MANY_RE = re.compile(r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8})\s(?P<host>\S+)\ssshd\[(?P<pid>\d+)\]:\s"
                             r"Disconnecting: Too many authentication failures for (?:invalid user )?(?P<user>\S+)")
SSH_PID_IP_RE = re.compile(r"sshd\[(?P<pid>\d+)\]:.*?(?P<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b)")
PID_SEARCH_LINES = 50

WIN_EVENTS = {
    4624: ("login", "success"),          # An account was successfully logged on
    4625: ("login", "failure"),          # An account failed to log on
    4720: ("user_created", "info"),      # A user account was created
    4732: ("group_add", "info"),         # A member was added to a security-enabled local group
    4740: ("lockout", "info"),           # A user account was locked out
    4688: ("process", "info"),           # A new process has been created
    1102: ("log_cleared", "info"),       # The audit log was cleared
}


def _pid_ip_lookup(lines):
    """pid -> [(line number, ip)] for every sshd line that names an IP."""
    seen = {}
    for i, line in enumerate(lines):
        m = SSH_PID_IP_RE.search(line)
        if m:
            seen.setdefault(m["pid"], []).append((i, m["ip"]))
    return seen


def parse_linux(text, year=2026):
    rows, lines = [], text.splitlines()
    pid_ips = None
    for i, raw in enumerate(lines):
        line = raw.strip()
        m = SSH_RE.match(line)
        if not m:
            t = SSH_TOO_MANY_RE.match(line)
            if t:
                pid_ips = pid_ips if pid_ips is not None else _pid_ip_lookup(lines)
                near = [(abs(j - i), ip) for j, ip in pid_ips.get(t["pid"], []) if abs(j - i) <= PID_SEARCH_LINES]
                ts = datetime.strptime(f"{year} {t['ts']}", "%Y %b %d %H:%M:%S")
                rows.append((ts, t["host"], t["user"], min(near)[1] if near else "unknown", "login", "failure",
                             "linux_auth", "", "too many authentication failures"))
            continue
        msg = m["msg"]
        if msg.startswith("Failed"):
            user, etype, status = m["u1"], "login", "failure"
        elif msg.startswith("Accepted"):
            user, etype, status = m["u2"], "login", "success"
        else:
            user, etype, status = m["u3"] or "(empty)", "invalid_user", "failure"
        ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S")
        rows.append((ts, m["host"], user, m["ip"], etype, status, "linux_auth", "", ""))
    return pd.DataFrame(rows, columns=COLUMNS)


def parse_windows(text):
    df = pd.read_csv(StringIO(text), dtype=str, keep_default_na=False)
    df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce")
    df = df[df["event_id"].isin(list(WIN_EVENTS))].copy()
    for col in ("ip", "target_user", "group", "command_line"):
        if col not in df:
            df[col] = ""
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    df["event_type"] = df["event_id"].map(lambda e: WIN_EVENTS[e][0])
    df["status"] = df["event_id"].map(lambda e: WIN_EVENTS[e][1])
    df["detail"] = df["group"].where(df["group"] != "", df["command_line"])
    df = df.rename(columns={"ip": "source_ip"})
    df["source_log"] = "windows_security"
    return df[COLUMNS].reset_index(drop=True)


def parse_text(text, year=2026):
    """Auto-detect format and parse. Empty/malformed input returns an empty DataFrame.
    `year` is used for syslog lines, which carry no year of their own."""
    if not text or not text.strip():
        return pd.DataFrame(columns=COLUMNS)
    if text.lstrip().lower().startswith("timestamp,host,event_id"):
        try:
            df = parse_windows(text)
        except Exception:
            df = pd.DataFrame(columns=COLUMNS)
    else:
        df = parse_linux(text, year)
    return df.sort_values("timestamp").reset_index(drop=True)


def parse_file(path):
    with open(path, "r", errors="ignore") as f:
        return parse_text(f.read())
