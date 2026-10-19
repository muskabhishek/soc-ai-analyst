"""Glue: raw log text -> parsed DataFrame -> alerts (detected, MITRE-mapped, scored)."""
from .parser import parse_text
from .detector import detect
from .mitre import map_alerts
from .scoring import score_alerts
from .pcap_parser import is_pcap, parse_pcap
from .net_detector import detect_network


def analyze_text(text, year=2026):
    df = parse_text(text, year)
    alerts = score_alerts(map_alerts(detect(df)))
    for i, a in enumerate(alerts, 1):
        a["alert_id"] = i
    return df, alerts


def analyze_file(path):
    """A log file or a packet capture -> (df, alerts)."""
    with open(path, "rb") as f:
        df, alerts, _ = analyze_bytes(f.read())
    return df, alerts


def analyze_pcap(data: bytes):
    """PCAP/PCAPNG bytes -> packet DataFrame + network alerts (detected, MITRE-mapped, scored)."""
    df = parse_pcap(data)
    alerts = score_alerts(map_alerts(detect_network(df)))
    for i, a in enumerate(alerts, 1):
        a["alert_id"] = i
    return df, alerts


def analyze_bytes(data: bytes, year=2026):
    """Any upload: a packet capture is detected by its magic bytes, everything else is treated as log text.
    Returns (df, alerts, kind) with kind 'pcap' or 'logs'."""
    if is_pcap(data):
        return (*analyze_pcap(data), "pcap")
    return (*analyze_text(data.decode("utf-8", errors="ignore"), year), "logs")
