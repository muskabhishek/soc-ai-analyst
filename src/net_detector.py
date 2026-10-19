"""Step 4b - Network detection rules for PCAP traffic. Python decides what is a threat; the LLM only explains.

Every alert carries a Wireshark display filter so the analyst can jump straight to the evidence packets.
"""
import math
from collections import Counter

import pandas as pd

from .detector import MAX_EVIDENCE, _best_window

NET_CONFIG = {
    "port_scan": {"min_ports": 20, "window_sec": 60},
    "net_brute_force": {"ports": {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC"},
                        "min_attempts": 15, "window_sec": 60},
    "suspicious_dns": {"long_label": 30, "min_entropy": 3.5, "entropy_min_len": 16, "min_queries": 5},
    "beaconing": {"min_connections": 6, "max_jitter": 0.10, "min_interval_sec": 10},
    "suspicious_download": {"extensions": (".exe", ".dll", ".ps1", ".hta", ".vbs", ".bat", ".scr", ".msi", ".jar")},
    "suspicious_port": {"ports": {4444: "Metasploit default listener", 1337: "common backdoor port",
                                  31337: "Back Orifice / 'elite' backdoor", 6667: "IRC, used for botnet C2",
                                  5555: "Android ADB / common RAT port"}},
}
NET_RULES = {"port_scan", "net_brute_force", "cleartext_credentials", "suspicious_dns", "beaconing",
             "suspicious_download", "suspicious_port"}
EVIDENCE_COLS = ["timestamp", "source_ip", "src_port", "dst_ip", "dst_port", "proto", "flags", "length", "info"]


def _alert(rule, src, sub, desc, wfilter, count=None, peer=None, users=()):
    ev = sub.head(MAX_EVIDENCE)[EVIDENCE_COLS].copy()
    ev["timestamp"] = ev["timestamp"].astype(str)
    return {
        "rule": rule, "source_ip": src, "peer_ip": peer, "host": peer or "-",
        "users": sorted({u for u in users if u})[:20], "count": int(count if count is not None else len(sub)),
        "start": str(sub["timestamp"].min()), "end": str(sub["timestamp"].max()),
        "description": desc, "evidence": ev.to_dict("records"), "wireshark_filter": wfilter, "data_source": "pcap",
    }


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _syn_only(df):
    return df[(df["flags"] == "S") & (df["proto"].isin(["TCP", "HTTP", "FTP"]))]


def detect_network(df, config=None):
    cfg = config or NET_CONFIG
    alerts = []
    if df is None or df.empty:
        return alerts
    df = df.sort_values("timestamp").reset_index(drop=True)
    syn = _syn_only(df)

    # 1. Port scan: one source probes many ports on one target (SYN without completing the handshake)
    c = cfg["port_scan"]
    for (src, dst), g in syn.groupby(["source_ip", "dst_ip"]):
        w, n = _best_window(g, pd.Timedelta(seconds=c["window_sec"]), lambda x: x["dst_port"].nunique())
        if w is not None and n >= c["min_ports"]:
            alerts.append(_alert("port_scan", src, w,
                f"{src} probed {n} different ports on {dst} within {c['window_sec']} seconds (SYN scan).",
                f"ip.src=={src} && ip.dst=={dst} && tcp.flags.syn==1 && tcp.flags.ack==0", count=n, peer=dst))

    # 2. Brute force seen on the wire: many new connections to a login service
    c = cfg["net_brute_force"]
    for (src, dst, port), g in syn[syn["dst_port"].isin(list(c["ports"]))].groupby(["source_ip", "dst_ip", "dst_port"]):
        w, n = _best_window(g, pd.Timedelta(seconds=c["window_sec"]), len)
        if w is not None and n >= c["min_attempts"]:
            svc = c["ports"][port]
            alerts.append(_alert("net_brute_force", src, w,
                f"{n} new {svc} connections from {src} to {dst}:{port} within {c['window_sec']} seconds "
                f"- password guessing against {svc}.",
                f"ip.src=={src} && ip.dst=={dst} && tcp.dstport=={port} && tcp.flags.syn==1 && tcp.flags.ack==0",
                count=n, peer=dst))

    # 3. Cleartext credentials: FTP USER/PASS or HTTP Basic auth readable by anyone on the path
    creds = df[df["cred_proto"] != ""]
    for (src, dst, proto), g in creds.groupby(["source_ip", "dst_ip", "cred_proto"]):
        users = [u for u in g["cred_user"] if u]
        port = int(g["dst_port"].iloc[0])
        wf = (f'ip.src=={src} && ip.dst=={dst} && ftp.request.command in {{"USER" "PASS"}}' if proto == "FTP"
              else f"ip.src=={src} && ip.dst=={dst} && http.authorization")
        alerts.append(_alert("cleartext_credentials", src, g,
            f"{proto} credentials for {', '.join(repr(u) for u in sorted(set(users))) or 'an account'} sent unencrypted "
            f"from {src} to {dst}:{port} - anyone on the network path can read them.",
            wf, count=len(g), peer=dst, users=users))

    # 4. Suspicious DNS: very long or random-looking names (DNS tunnelling / exfiltration, DGA malware)
    c = cfg["suspicious_dns"]
    q = df[df["dns_query"] != ""].copy()
    if not q.empty:
        def odd(name):
            labels = name.split(".")[:-2] or [name]
            longest = max(labels, key=len)
            return len(longest) >= c["long_label"] or (len(longest) >= c["entropy_min_len"]
                                                       and entropy(longest) >= c["min_entropy"])
        q = q[q["dns_query"].map(odd)]
        for src, g in q.groupby("source_ip"):
            if len(g) >= c["min_queries"]:
                parent = Counter(".".join(n.split(".")[-2:]) for n in g["dns_query"]).most_common(1)[0][0]
                alerts.append(_alert("suspicious_dns", src, g,
                    f"{src} made {len(g)} DNS queries with long or random-looking names, mostly under '{parent}' "
                    f"- possible DNS tunnelling or malware-generated domains.",
                    f'ip.src=={src} && dns.flags.response==0 && dns.qry.name contains "{parent}"',
                    peer=g["dst_ip"].mode().iloc[0]))

    # 5. Beaconing: connections to the same server at near-constant intervals (malware calling home)
    c = cfg["beaconing"]
    for (src, dst, port), g in syn.groupby(["source_ip", "dst_ip", "dst_port"]):
        if len(g) < c["min_connections"]:
            continue
        gaps = g["timestamp"].diff().dt.total_seconds().dropna()
        mean = gaps.mean()
        if mean >= c["min_interval_sec"] and gaps.std() / mean <= c["max_jitter"]:
            alerts.append(_alert("beaconing", src, g,
                f"{src} connected to {dst}:{port} {len(g)} times every {mean:.0f}s (+/-{gaps.std():.1f}s) "
                f"- regular check-ins typical of malware command-and-control.",
                f"ip.src=={src} && ip.dst=={dst} && tcp.dstport=={port} && tcp.flags.syn==1 && tcp.flags.ack==0",
                peer=dst))

    # 6. Executable or script downloaded over plain HTTP
    exts = cfg["suspicious_download"]["extensions"]
    dl = df[(df["http_method"] == "GET") & df["http_uri"].str.lower().str.split("?").str[0].str.endswith(exts)]
    for (src, dst), g in dl.groupby(["source_ip", "dst_ip"]):
        files = ", ".join(sorted(set(g["http_host"] + g["http_uri"])))[:200]
        alerts.append(_alert("suspicious_download", src, g,
            f"{src} downloaded executable content over unencrypted HTTP from {dst}: {files}.",
            f'ip.src=={src} && ip.dst=={dst} && http.request.uri matches "\\\\.(exe|dll|ps1|hta|vbs|bat|scr|msi|jar)"',
            peer=dst))

    # 7. Connections to ports associated with backdoors and C2 frameworks
    ports = cfg["suspicious_port"]["ports"]
    for (src, dst, port), g in syn[syn["dst_port"].isin(list(ports))].groupby(["source_ip", "dst_ip", "dst_port"]):
        alerts.append(_alert("suspicious_port", src, g,
            f"{src} connected to {dst}:{port} ({ports[port]}).",
            f"ip.addr=={src} && ip.addr=={dst} && tcp.port=={port}", peer=dst))

    return alerts
