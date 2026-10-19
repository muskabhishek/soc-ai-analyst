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
             "suspicious_download", "suspicious_port", "remote_shell", "exploit_shellcode"}
SIG_FILTERS = {"cmd_banner": 'tcp contains "Microsoft Windows"', "root_shell": 'tcp contains "uid=0(root)"'}
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

    # 6. Executable or script downloaded over plain HTTP: by file extension in the request, or by the file itself
    #    (Windows "MZ ... This program cannot be run in DOS mode" header / executable content type) in the response,
    #    which also catches executables renamed to .jpg or .bin
    exts = cfg["suspicious_download"]["extensions"]
    dl = df[(df["http_method"] == "GET") & df["http_uri"].str.lower().str.split("?").str[0].str.endswith(exts)]
    pe = df[df["signature"] == "pe_file"]
    pairs = {(r.source_ip, r.dst_ip) for r in dl.itertuples()} | {(r.dst_ip, r.source_ip) for r in pe.itertuples()}
    for client, server in sorted(pairs):
        g = pd.concat([dl[(dl["source_ip"] == client) & (dl["dst_ip"] == server)],
                       pe[(pe["source_ip"] == server) & (pe["dst_ip"] == client)]]).sort_values("timestamp")
        reqs = g[g["http_method"] == "GET"]
        files = ", ".join(sorted(set(reqs["http_host"] + reqs["http_uri"])))[:200] or "file name not in the request"
        how = "executable file header seen in the response" if len(g) > len(reqs) else "executable file extension"
        alerts.append(_alert("suspicious_download", client, g,
            f"{client} downloaded executable content over unencrypted HTTP from {server} ({how}): {files}.",
            f'ip.addr=={client} && ip.addr=={server} && (http.request.uri matches "\\\\.(exe|dll|ps1|hta|vbs|bat|scr|msi|jar)" '
            f'|| tcp contains "This program cannot be run in DOS mode")', peer=server))

    # 7. Connections to ports associated with backdoors and C2 frameworks - only when the other side ANSWERED
    #    (SYN-ACK), so a port scan that merely touches these ports does not raise extra alerts
    ports = cfg["suspicious_port"]["ports"]
    answered = {(r.dst_ip, r.source_ip, r.src_port) for r in df[df["flags"] == "SA"].itertuples()}
    for (src, dst, port), g in syn[syn["dst_port"].isin(list(ports))].groupby(["source_ip", "dst_ip", "dst_port"]):
        if (src, dst, port) in answered:
            alerts.append(_alert("suspicious_port", src, g,
                f"{src} opened a connection to {dst}:{port} ({ports[port]}).",
                f"ip.addr=={src} && ip.addr=={dst} && tcp.port=={port}", peer=dst))

    # 8. Remote shell: a command-prompt banner or root `id` output travelling over the network
    for (src, dst), g in df[df["signature"].isin(["cmd_banner", "root_shell"])].groupby(["source_ip", "dst_ip"]):
        kind = g["signature"].iloc[0]
        shell = "Windows command prompt" if kind == "cmd_banner" else "root shell"
        ports_used = ", ".join(sorted({f"{s}->{d}" for s, d in zip(g["src_port"], g["dst_port"])}))[:120]
        alerts.append(_alert("remote_shell", src, g,
            f"{src} sent a {shell} to {dst} (ports {ports_used}) - someone at {dst} is typing commands on {src}.",
            f"ip.src=={src} && ip.dst=={dst} && {SIG_FILTERS[kind]}", peer=dst))

    # 9. Exploit payload: Metasploit-style shellcode stager bytes on the wire
    for (src, dst), g in df[df["signature"] == "shellcode"].groupby(["source_ip", "dst_ip"]):
        alerts.append(_alert("exploit_shellcode", src, g,
            f"{src} sent shellcode (Metasploit stager byte pattern) to {dst} - an exploit is being delivered.",
            f"ip.src=={src} && ip.dst=={dst} && (tcp contains fc:e8:89:00:00:00 || tcp contains fc:e8:82:00:00:00)",
            peer=dst))

    return alerts
