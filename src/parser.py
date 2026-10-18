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
    r"(?P<msg>Failed password for (?:invalid user )?(?P<u1>\S+)|Accepted \w+ for (?P<u2>\S+)|Invalid user (?P<u3>\S+))"
    r".*?from\s(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
WIN_EVENTS = {
    4624: ("login", "success"),          # An account was successfully logged on
    4625: ("login", "failure"),          # An account failed to log on
    4720: ("user_created", "info"),      # A user account was created
    4732: ("group_add", "info"),         # A member was added to a security-enabled local group
    4740: ("lockout", "info"),           # A user account was locked out
    4688: ("process", "info"),           # A new process has been created
    1102: ("log_cleared", "info"),       # The audit log was cleared
}


def parse_linux(text, year=2026):
    rows = []
    for line in text.splitlines():
        m = SSH_RE.match(line.strip())
        if not m:
            continue
        msg = m["msg"]
        if msg.startswith("Failed"):
            user, etype, status = m["u1"], "login", "failure"
        elif msg.startswith("Accepted"):
            user, etype, status = m["u2"], "login", "success"
        else:
            user, etype, status = m["u3"], "invalid_user", "failure"
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


def parse_text(text):
    """Auto-detect format and parse. Empty/malformed input returns an empty DataFrame."""
    if not text or not text.strip():
        return pd.DataFrame(columns=COLUMNS)
    if text.lstrip().lower().startswith("timestamp,host,event_id"):
        try:
            df = parse_windows(text)
        except Exception:
            df = pd.DataFrame(columns=COLUMNS)
    else:
        df = parse_linux(text)
    return df.sort_values("timestamp").reset_index(drop=True)


def parse_file(path):
    with open(path, "r", errors="ignore") as f:
        return parse_text(f.read())
