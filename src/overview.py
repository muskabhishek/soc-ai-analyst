"""Chart-ready summary of one analysed upload, stored with it so any front end can draw the overview without
re-reading the raw events: KPIs, an activity timeline, top sources, severity and MITRE counts, and for packet
captures the most-contacted ports, DNS queries and HTTP requests."""
from collections import Counter

import pandas as pd

BUCKETS = [("1min", 60), ("5min", 300), ("15min", 900), ("1h", 3600), ("6h", 21600), ("1D", 86400)]
MAX_POINTS = 60


def _bucket(span_seconds):
    for freq, secs in BUCKETS:
        if span_seconds / secs <= MAX_POINTS:
            return freq, secs
    return BUCKETS[-1]


def build_overview(df, alerts, kind):
    if df is None or df.empty:
        return None
    is_pcap = kind == "pcap"
    ts = df["timestamp"]
    span = max((ts.max() - ts.min()).total_seconds(), 1)
    freq, secs = _bucket(span)
    series_col = "proto" if is_pcap else "status"
    t = df.assign(bucket=ts.dt.floor(freq)).groupby(["bucket", series_col]).size().unstack(fill_value=0)
    series = [str(c) for c in t.columns]
    timeline = [{"t": b.isoformat(), **{str(k): int(v) for k, v in row.items()}} for b, row in t.iterrows()]

    alert_ips = {a["source_ip"] for a in alerts}
    src = df if is_pcap else df[df["status"] == "failure"]
    top_sources = [{"ip": ip, "count": int(n), "alerted": ip in alert_ips}
                   for ip, n in src["source_ip"].value_counts().head(8).items()]
    failures = int((df["status"] == "failure").sum()) if "status" in df else 0
    sev = Counter(a["severity"] for a in alerts)
    mitre = Counter(f"{a['mitre']['id']} {a['mitre']['name']}" for a in alerts)

    out = {
        "kind": kind,
        "kpis": {
            "events": int(len(df)), "alerts": len(alerts),
            "critical_high": sev.get("Critical", 0) + sev.get("High", 0),
            "suspicious_ips": len(alert_ips), "failed_logins": failures,
            "hosts_seen": int(len(set(df["source_ip"]) | set(df.get("dst_ip", pd.Series(dtype=str))))),
            "span_hours": round(span / 3600, 2), "first": ts.min().isoformat(), "last": ts.max().isoformat(),
        },
        "timeline": {"bucket": freq, "bucket_seconds": secs, "series": series, "points": timeline},
        "top_sources": top_sources,
        "severity": {k: sev.get(k, 0) for k in ("Critical", "High", "Medium", "Low")},
        "mitre": [{"technique": k, "count": v} for k, v in mitre.most_common()],
    }
    if is_pcap:
        syn = df[(df["flags"] == "S") & (df["dst_port"] > 0)]
        out["top_ports"] = [{"port": int(p), "count": int(n)} for p, n in syn["dst_port"].value_counts().head(10).items()]
        dns = df[df["dns_query"] != ""].groupby(["source_ip", "dns_query"]).size().sort_values(ascending=False)
        out["dns"] = [{"source": s, "query": q, "count": int(n)} for (s, q), n in dns.head(25).items()]
        http = df[df["http_method"] != ""].head(40)
        out["http"] = [{"time": r.timestamp.isoformat(), "source": r.source_ip, "method": r.http_method,
                        "host": r.http_host, "uri": r.http_uri[:160]} for r in http.itertuples()]
    return out
