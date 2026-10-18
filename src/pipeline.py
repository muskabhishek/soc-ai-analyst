"""Glue: raw log text -> parsed DataFrame -> alerts (detected, MITRE-mapped, scored)."""
from .parser import parse_text
from .detector import detect
from .mitre import map_alerts
from .scoring import score_alerts


def analyze_text(text):
    df = parse_text(text)
    alerts = score_alerts(map_alerts(detect(df)))
    for i, a in enumerate(alerts, 1):
        a["alert_id"] = i
    return df, alerts


def analyze_file(path):
    with open(path, "r", errors="ignore") as f:
        return analyze_text(f.read())
