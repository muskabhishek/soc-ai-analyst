"""Step 8a - SQLite storage for events, alerts and reports."""
import json
import os
import sqlite3

DB_PATH = os.getenv("SOC_DB", "data/soc.db")


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
        """)


def save_analysis(filename, df, alerts, path=None):
    """Store one upload with its events and alerts. Returns (upload_id, list of alert DB ids)."""
    with conn(path) as c:
        up = c.execute("INSERT INTO uploads(filename, n_events) VALUES(?,?)", (filename, len(df))).lastrowid
        if len(df):
            d = df.copy()
            d["timestamp"] = d["timestamp"].astype(str)
            c.executemany(
                "INSERT INTO logs(upload_id,timestamp,host,user,source_ip,event_type,status,source_log) VALUES(?,?,?,?,?,?,?,?)",
                [(up, *r) for r in d[["timestamp", "host", "user", "source_ip", "event_type", "status", "source_log"]].itertuples(index=False)])
        ids = []
        for a in alerts:
            cur = c.execute(
                "INSERT INTO alerts(upload_id,rule,severity,risk_score,source_ip,host,count,start,end,mitre_id,payload) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (up, a["rule"], a["severity"], a["risk_score"], a["source_ip"], a["host"], a["count"], a["start"], a["end"],
                 a["mitre"]["id"], json.dumps(a, default=str)))
            ids.append(cur.lastrowid)
        return up, ids


def list_alerts(upload_id=None, path=None):
    q, args = "SELECT id,upload_id,rule,severity,risk_score,source_ip,host,count,start,end,mitre_id FROM alerts", ()
    if upload_id:
        q, args = q + " WHERE upload_id=?", (upload_id,)
    with conn(path) as c:
        return [dict(r) for r in c.execute(q + " ORDER BY risk_score DESC", args)]


def get_alert(alert_id, path=None):
    with conn(path) as c:
        r = c.execute("SELECT payload FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not r:
            return None
        a = json.loads(r["payload"])
        a["db_id"] = alert_id
        rep = c.execute("SELECT text,source,warnings FROM reports WHERE alert_id=?", (alert_id,)).fetchone()
        a["report"] = {"text": rep["text"], "source": rep["source"], "warnings": json.loads(rep["warnings"])} if rep else None
        return a


def save_report(alert_id, text, source, warnings, path=None):
    with conn(path) as c:
        c.execute("INSERT OR REPLACE INTO reports(alert_id,text,source,warnings) VALUES(?,?,?,?)",
                  (alert_id, text, source, json.dumps(warnings)))


def stats(path=None):
    with conn(path) as c:
        return {
            "uploads": c.execute("SELECT COUNT(*) FROM uploads").fetchone()[0],
            "events": c.execute("SELECT COUNT(*) FROM logs").fetchone()[0],
            "alerts": c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "by_severity": {r[0]: r[1] for r in c.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")},
        }
