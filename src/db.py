"""Step 8a - SQLite storage for events, alerts, reports and the alert case workflow."""
import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.getenv("SOC_DB", "data/soc.db")

STATUSES = ["New", "In Progress", "Escalated", "Closed"]
DISPOSITIONS = ["True Positive", "Benign True Positive", "False Positive"]

# columns added after the first version; init_db() adds them to an existing database
_MIGRATIONS = {
    "logs": {"target_user": "TEXT", "detail": "TEXT"},
    "alerts": {"status": "TEXT DEFAULT 'New'", "disposition": "TEXT", "assignee": "TEXT", "created_at": "TEXT",
               "acknowledged_at": "TEXT", "closed_at": "TEXT"},
}
_ALERT_COLS = ("id,upload_id,rule,severity,risk_score,source_ip,host,count,start,end,mitre_id,"
               "status,disposition,assignee,created_at,acknowledged_at,closed_at")


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def conn(path=None):
    path = path or DB_PATH
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    c = sqlite3.connect(path)
    c.row_factory = sqlite3.Row
    return c


def init_db(path=None):
    with conn(path) as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS uploads(id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, n_events INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT, upload_id INTEGER, timestamp TEXT,
            host TEXT, user TEXT, source_ip TEXT, event_type TEXT, status TEXT, source_log TEXT);
        CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, upload_id INTEGER, rule TEXT, severity TEXT,
            risk_score REAL, source_ip TEXT, host TEXT, count INTEGER, start TEXT, end TEXT, mitre_id TEXT, payload TEXT);
        CREATE TABLE IF NOT EXISTS reports(alert_id INTEGER PRIMARY KEY, text TEXT, source TEXT, warnings TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER, author TEXT,
            action TEXT, detail TEXT, created_at TEXT);
        """)
        for table, cols in _MIGRATIONS.items():
            have = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
            for col, typ in cols.items():
                if col not in have:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
        c.execute("UPDATE alerts SET status='New' WHERE status IS NULL")


def save_analysis(filename, df, alerts, path=None):
    """Store one upload with its events and alerts. Returns (upload_id, list of alert DB ids)."""
    cols = ["timestamp", "host", "user", "source_ip", "event_type", "status", "source_log", "target_user", "detail"]
    now = _now()
    with conn(path) as c:
        up = c.execute("INSERT INTO uploads(filename, n_events) VALUES(?,?)", (filename, len(df))).lastrowid
        if len(df):
            d = df.reindex(columns=cols, fill_value="").copy()
            d["timestamp"] = d["timestamp"].astype(str)
            c.executemany(
                f"INSERT INTO logs(upload_id,{','.join(cols)}) VALUES({','.join('?' * (len(cols) + 1))})",
                [(up, *r) for r in d.itertuples(index=False)])
        ids = []
        for a in alerts:
            cur = c.execute(
                "INSERT INTO alerts(upload_id,rule,severity,risk_score,source_ip,host,count,start,end,mitre_id,payload,"
                "status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'New',?)",
                (up, a["rule"], a["severity"], a["risk_score"], a["source_ip"], a["host"], a["count"], a["start"], a["end"],
                 a["mitre"]["id"], json.dumps(a, default=str), now))
            ids.append(cur.lastrowid)
            c.execute("INSERT INTO activity(alert_id,author,action,detail,created_at) VALUES(?,?,?,?,?)",
                      (cur.lastrowid, "system", "created", f"{a['severity']} alert raised by rule {a['rule']}", now))
        return up, ids


def list_alerts(upload_id=None, status=None, path=None):
    q, where, args = f"SELECT {_ALERT_COLS} FROM alerts", [], []
    if upload_id:
        where.append("upload_id=?"), args.append(upload_id)
    if status:
        where.append("status=?"), args.append(status)
    if where:
        q += " WHERE " + " AND ".join(where)
    with conn(path) as c:
        return [dict(r) for r in c.execute(q + " ORDER BY risk_score DESC, id", args)]


def get_alert(alert_id, path=None):
    with conn(path) as c:
        r = c.execute(f"SELECT payload,{_ALERT_COLS} FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not r:
            return None
        a = json.loads(r["payload"])
        a.update({k: r[k] for k in ("status", "disposition", "assignee", "created_at", "acknowledged_at", "closed_at")})
        a["db_id"] = alert_id
        rep = c.execute("SELECT text,source,warnings FROM reports WHERE alert_id=?", (alert_id,)).fetchone()
        a["report"] = {"text": rep["text"], "source": rep["source"], "warnings": json.loads(rep["warnings"])} if rep else None
        return a


def save_report(alert_id, text, source, warnings, path=None):
    with conn(path) as c:
        c.execute("INSERT OR REPLACE INTO reports(alert_id,text,source,warnings) VALUES(?,?,?,?)",
                  (alert_id, text, source, json.dumps(warnings)))


# ---------------- case workflow ----------------

def _log(c, alert_id, author, action, detail):
    c.execute("INSERT INTO activity(alert_id,author,action,detail,created_at) VALUES(?,?,?,?,?)",
              (alert_id, author or "analyst", action, detail, _now()))


def update_status(alert_id, status, author="analyst", disposition=None, note=None, path=None):
    """Move an alert through New -> In Progress / Escalated -> Closed. Closing requires a disposition."""
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    if status == "Closed" and disposition not in DISPOSITIONS:
        raise ValueError(f"closing an alert needs a disposition: {DISPOSITIONS}")
    with conn(path) as c:
        row = c.execute("SELECT status, acknowledged_at, closed_at FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not row:
            raise KeyError(alert_id)
        now = _now()
        ack = row["acknowledged_at"] or (now if status != "New" else None)
        closed = (row["closed_at"] or now) if status == "Closed" else None
        c.execute("UPDATE alerts SET status=?, disposition=?, acknowledged_at=?, closed_at=? WHERE id=?",
                  (status, disposition if status == "Closed" else None, ack, closed, alert_id))
        if row["status"] != status:
            _log(c, alert_id, author, "status", f"{row['status']} -> {status}" + (f" ({disposition})" if closed else ""))
        if note:
            _log(c, alert_id, author, "note", note)


def assign(alert_id, assignee, author="analyst", path=None):
    with conn(path) as c:
        if not c.execute("UPDATE alerts SET assignee=? WHERE id=?", (assignee, alert_id)).rowcount:
            raise KeyError(alert_id)
        _log(c, alert_id, author, "assign", f"assigned to {assignee}")


def add_note(alert_id, text, author="analyst", path=None):
    with conn(path) as c:
        if not c.execute("SELECT 1 FROM alerts WHERE id=?", (alert_id,)).fetchone():
            raise KeyError(alert_id)
        _log(c, alert_id, author, "note", text)


def get_activity(alert_id, path=None):
    with conn(path) as c:
        return [dict(r) for r in c.execute(
            "SELECT author,action,detail,created_at FROM activity WHERE alert_id=? ORDER BY id", (alert_id,))]


def case_metrics(path=None):
    """SOC KPIs: queue by status, mean time to acknowledge / resolve, false-positive rate overall and per rule."""
    with conn(path) as c:
        by_status = {s: 0 for s in STATUSES}
        by_status.update({r[0]: r[1] for r in c.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status")})
        mins = "(julianday({end}) - julianday(created_at)) * 1440"
        mtta = c.execute(f"SELECT AVG({mins.format(end='acknowledged_at')}) FROM alerts WHERE acknowledged_at IS NOT NULL").fetchone()[0]
        mttr = c.execute(f"SELECT AVG({mins.format(end='closed_at')}) FROM alerts WHERE closed_at IS NOT NULL").fetchone()[0]
        closed = by_status["Closed"]
        fp = c.execute("SELECT COUNT(*) FROM alerts WHERE disposition='False Positive'").fetchone()[0]
        per_rule = [dict(r) for r in c.execute("""
            SELECT rule, COUNT(*) AS closed, SUM(disposition='False Positive') AS false_positives,
                   ROUND(100.0 * SUM(disposition='False Positive') / COUNT(*), 1) AS fp_rate_pct
            FROM alerts WHERE status='Closed' GROUP BY rule ORDER BY fp_rate_pct DESC, closed DESC""")]
        return {
            "by_status": by_status,
            "open": sum(by_status.values()) - closed,
            "mtta_minutes": round(mtta, 1) if mtta is not None else None,
            "mttr_minutes": round(mttr, 1) if mttr is not None else None,
            "closed": closed,
            "false_positive_rate_pct": round(100 * fp / closed, 1) if closed else None,
            "fp_rate_by_rule": per_rule,
        }


def correlations(path=None):
    """IPs that triggered alerts in BOTH log files and packet captures: one attacker seen by two independent
    sources is stronger evidence than either alone, so these are listed first for triage."""
    from .net_detector import NET_RULES
    marks = ",".join("?" * len(NET_RULES))
    with conn(path) as c:
        rows = c.execute(f"""
            SELECT source_ip,
                   GROUP_CONCAT(DISTINCT CASE WHEN rule NOT IN ({marks}) THEN rule END) AS log_rules,
                   GROUP_CONCAT(DISTINCT CASE WHEN rule IN ({marks}) THEN rule END) AS network_rules,
                   COUNT(*) AS alerts, MAX(risk_score) AS max_risk, MIN(start) AS first_seen, MAX(end) AS last_seen,
                   SUM(status != 'Closed') AS open_alerts
            FROM alerts WHERE source_ip NOT IN ('unknown', '')
            GROUP BY source_ip
            HAVING SUM(rule IN ({marks})) > 0 AND SUM(rule NOT IN ({marks})) > 0
            ORDER BY max_risk DESC""", [*NET_RULES] * 4).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["log_rules"] = sorted(d["log_rules"].split(","))
            d["network_rules"] = sorted(d["network_rules"].split(","))
            out.append(d)
        return out


def stats(path=None):
    with conn(path) as c:
        return {
            "uploads": c.execute("SELECT COUNT(*) FROM uploads").fetchone()[0],
            "events": c.execute("SELECT COUNT(*) FROM logs").fetchone()[0],
            "alerts": c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "by_severity": {r[0]: r[1] for r in c.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")},
        }
