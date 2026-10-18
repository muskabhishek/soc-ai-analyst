"""Step 4 - Rule-based detection engine. Python decides what is a threat; the LLM only explains."""
import pandas as pd

CONFIG = {
    "brute_force": {"min_failures": 10, "window_min": 5},
    "password_spraying": {"min_users": 5, "window_min": 10},
    "success_after_failures": {"min_failures": 5, "window_min": 10},
    "invalid_user_probing": {"min_events": 5, "window_min": 10},
    "odd_hour_login": {"start_hour": 0, "end_hour": 5},
    "admin_group_add": {"groups": ["administrators", "domain admins", "enterprise admins", "schema admins"]},
    "suspicious_powershell": {"pattern": r"(?i)powershell.*(?:\s-e(?:nc|ncodedcommand)?\s|\s-w(?:indowstyle)?\s+hidden|"
                                         r"iex\b|invoke-expression|downloadstring|frombase64string)"},
}
MAX_EVIDENCE = 50


def _evidence(df):
    ev = df.head(MAX_EVIDENCE).copy()
    ev["timestamp"] = ev["timestamp"].astype(str)
    return ev.to_dict("records")


def _make(rule, ip, sub, desc, count=None):
    return {
        "rule": rule, "source_ip": ip, "host": sub["host"].iloc[0],
        "users": sorted(sub["user"].astype(str).unique().tolist())[:20],
        "count": int(count if count is not None else len(sub)),
        "start": str(sub["timestamp"].min()), "end": str(sub["timestamp"].max()),
        "description": desc, "evidence": _evidence(sub),
    }


def _best_window(sub, window, metric):
    """Slide a time window over sub (sorted by time); return the window slice with the highest metric."""
    best, best_val = None, 0
    ts = sub["timestamp"].reset_index(drop=True)
    j = 0
    for i in range(len(sub)):
        while ts[i] - ts[j] > window:
            j += 1
        w = sub.iloc[j:i + 1]
        val = metric(w)
        if val > best_val:
            best, best_val = w, val
    return best, best_val


def detect(df, config=None):
    cfg = config or CONFIG
    alerts = []
    if df is None or df.empty:
        return alerts
    df = df.sort_values("timestamp").reset_index(drop=True)
    fails = df[(df["status"] == "failure") & (df["event_type"] == "login")]
    invalid = df[df["event_type"] == "invalid_user"]
    success = df[(df["status"] == "success") & (df["event_type"] == "login")]

    # 1. Brute force: many failures from one IP in a short window
    c = cfg["brute_force"]
    for ip, g in fails.groupby("source_ip"):
        w, n = _best_window(g, pd.Timedelta(minutes=c["window_min"]), len)
        if w is not None and n >= c["min_failures"]:
            alerts.append(_make("brute_force", ip, w,
                f"{n} failed logins from {ip} within {c['window_min']} minutes (users targeted: {w['user'].nunique()})."))

    # 2. Password spraying: one IP failing against many different usernames
    c = cfg["password_spraying"]
    for ip, g in pd.concat([fails, invalid]).sort_values("timestamp").groupby("source_ip"):
        w, n = _best_window(g, pd.Timedelta(minutes=c["window_min"]), lambda x: x["user"].nunique())
        if w is not None and n >= c["min_users"] and (w["event_type"] == "login").sum() >= c["min_users"]:
            alerts.append(_make("password_spraying", ip, w,
                f"{ip} attempted logins against {n} different usernames within {c['window_min']} minutes."))

    # 3. Success after failures: a login succeeded after a burst of failures from the same IP
    c = cfg["success_after_failures"]
    for _, s in success.iterrows():
        prior = fails[(fails["source_ip"] == s["source_ip"]) & (fails["timestamp"] < s["timestamp"]) &
                      (fails["timestamp"] >= s["timestamp"] - pd.Timedelta(minutes=c["window_min"]))]
        if len(prior) >= c["min_failures"]:
            sub = pd.concat([prior, s.to_frame().T]).sort_values("timestamp")
            sub["timestamp"] = pd.to_datetime(sub["timestamp"])
            alerts.append(_make("success_after_failures", s["source_ip"], sub,
                f"Successful login for '{s['user']}' from {s['source_ip']} right after {len(prior)} failed attempts - possible account compromise.",
                count=len(prior)))

    # 4. Invalid user probing
    c = cfg["invalid_user_probing"]
    for ip, g in invalid.groupby("source_ip"):
        w, n = _best_window(g, pd.Timedelta(minutes=c["window_min"]), len)
        if w is not None and n >= c["min_events"]:
            alerts.append(_make("invalid_user_probing", ip, w,
                f"{n} attempts with non-existent usernames from {ip} - account enumeration."))

    # 5. Odd-hour successful login
    c = cfg["odd_hour_login"]
    odd = success[(success["timestamp"].dt.hour >= c["start_hour"]) & (success["timestamp"].dt.hour < c["end_hour"])]
    for _, r in odd.iterrows():
        sub = r.to_frame().T
        sub["timestamp"] = pd.to_datetime(sub["timestamp"])
        alerts.append(_make("odd_hour_login", r["source_ip"], sub,
            f"Successful login for '{r['user']}' at {r['timestamp']:%H:%M} (outside normal hours) from {r['source_ip']}.", count=1))

    # 6-10. Windows host events: each matching event is an alert on its own
    def per_event(rows, rule, desc):
        for _, r in rows.iterrows():
            sub = r.to_frame().T
            sub["timestamp"] = pd.to_datetime(sub["timestamp"])
            alerts.append(_make(rule, r["source_ip"], sub, desc(r), count=1))

    if "target_user" in df:
        et = df["event_type"]
        per_event(df[et == "user_created"], "new_account_created",
                  lambda r: f"New account '{r['target_user']}' created by '{r['user']}' on {r['host']}.")
        groups = set(cfg["admin_group_add"]["groups"])
        per_event(df[(et == "group_add") & df["detail"].str.lower().isin(groups)], "admin_group_add",
                  lambda r: f"'{r['target_user']}' added to privileged group '{r['detail']}' by '{r['user']}' on {r['host']}.")
        per_event(df[et == "lockout"], "account_lockout",
                  lambda r: f"Account '{r['target_user'] or r['user']}' locked out on {r['host']} after repeated failed logons.")
        per_event(df[(et == "process") & df["detail"].str.contains(cfg["suspicious_powershell"]["pattern"], regex=True)],
                  "suspicious_powershell",
                  lambda r: f"Suspicious PowerShell run by '{r['user']}' on {r['host']}: {r['detail'][:120]}")
        per_event(df[et == "log_cleared"], "audit_log_cleared",
                  lambda r: f"Security audit log cleared by '{r['user']}' on {r['host']} - possible cover-up of activity.")

    # Deduplicate: a success_after_failures alert supersedes nothing, but drop exact duplicates
    seen, uniq = set(), []
    for a in alerts:
        k = (a["rule"], a["source_ip"], a["start"])
        if k not in seen:
            seen.add(k)
            uniq.append(a)
    return uniq
