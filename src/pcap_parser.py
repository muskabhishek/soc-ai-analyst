"""Step 3b - Parse a PCAP / PCAPNG capture (what Wireshark saves) into one row per packet.

Extracts the fields a SOC analyst filters on in Wireshark: addresses, ports, TCP flags, DNS queries,
HTTP requests and cleartext credentials (FTP USER/PASS, HTTP Basic auth). Passwords are masked at parse time,
so they never reach the database, the dashboard or the LLM prompt.
"""
import base64
import binascii
import io
import logging
import re

logging.getLogger("scapy").setLevel(logging.ERROR)   # no "libpcap provider" noise: we only read files

import pandas as pd
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether  # noqa: F401  (registers the Ethernet link type for the reader)
from scapy.packet import Raw
from scapy.utils import PcapReader

MAX_PACKETS = 500_000
PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")

COLUMNS = ["timestamp", "source_ip", "src_port", "dst_ip", "dst_port", "proto", "flags", "length",
           "dns_query", "http_method", "http_host", "http_uri", "http_user_agent", "cred_proto", "cred_user",
           "signature", "info",
           # common-schema columns so captures are stored next to log events in the database
           "host", "user", "event_type", "status", "source_log", "detail"]

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")
BASIC_RE = re.compile(rb"^authorization:\s*basic\s+([A-Za-z0-9+/=]+)", re.I | re.M)
FORM_PASS_RE = re.compile(rb"(?:^|&)(?:pass|password|passwd|pwd|pass_word)=([^&\s]*)", re.I)
FORM_USER_RE = re.compile(rb"(?:^|&)(?:user|username|login|email|uname|usr)=([^&\s]*)", re.I)
EXE_TYPES = (b"application/x-msdownload", b"application/x-dosexec", b"application/x-msdos-program",
             b"application/vnd.microsoft.portable-executable")

# Payload signatures, the same idea as classic IDS rules (Snort/Suricata "ATTACK-RESPONSES" and shellcode rules)
SIGNATURES = [
    ("cmd_banner", re.compile(rb"Microsoft Windows(?: \w+)? \[Version \d[\d.]*\]")),          # Windows cmd.exe banner
    ("root_shell", re.compile(rb"uid=0\(root\) gid=\d+\(\w+\)")),                             # `id` output as root
    ("shellcode", re.compile(rb"\xfc\xe8[\x82\x89]\x00\x00\x00|\xfc\x48\x83\xe4\xf0\xe8")),   # Metasploit stagers
]
# A Windows executable is only reported when it is the START of a downloaded file (first bytes of an HTTP response
# body). Matching "MZ" anywhere would flag executables embedded inside big archives or ISO images.
PE_START_RE = re.compile(rb"^MZ.{0,200}This program cannot be run in DOS mode", re.S)


def is_pcap(data: bytes) -> bool:
    return data[:4] in PCAP_MAGICS


def mask(secret: str) -> str:
    """Keep only the first character: enough to confirm a leak, useless to an attacker."""
    return (secret[:1] + "***") if secret else "***"


def _http(payload: bytes):
    head = payload.split(b"\r\n\r\n", 1)[0]
    lines = head.split(b"\r\n")
    parts = lines[0].decode("latin-1").split(" ")
    method, uri = parts[0], parts[1] if len(parts) > 1 else ""
    hdr = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            hdr[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    user = None
    m = BASIC_RE.search(head)
    if m:
        try:
            u, _, p = base64.b64decode(m.group(1)).decode("latin-1").partition(":")
            user = (u, mask(p))
        except (binascii.Error, ValueError):
            pass
    return method, uri, hdr.get("host", ""), hdr.get("user-agent", ""), user


def _form_creds(body: bytes):
    """username/password fields of an urlencoded HTML form body -> (user, masked password) or None."""
    p = FORM_PASS_RE.search(body)
    if not p:
        return None
    u = FORM_USER_RE.search(body)
    return (u.group(1).decode("latin-1") if u else "", mask(p.group(1).decode("latin-1")))


def _row(pkt, pending_posts, pending_bodies):
    ip = pkt[IP] if IP in pkt else pkt[IPv6] if IPv6 in pkt else None
    if ip is None:
        return None
    r = dict.fromkeys(COLUMNS, "")
    r.update(timestamp=float(pkt.time), source_ip=ip.src, dst_ip=ip.dst, src_port=0, dst_port=0, length=len(pkt))
    if TCP in pkt:
        t = pkt[TCP]
        r.update(proto="TCP", src_port=t.sport, dst_port=t.dport, flags=str(t.flags))
        r["info"] = f"TCP {t.sport} -> {t.dport} [{t.flags}]"
        payload = bytes(t.payload) if Raw in pkt else b""
        flow = (ip.src, t.sport, ip.dst, t.dport)
        for name, sig in SIGNATURES:
            if payload and sig.search(payload):
                r.update(signature=name, info=f"TCP {t.sport} -> {t.dport} payload signature: {name}")
                break
        if payload.startswith(HTTP_METHODS):
            method, uri, host, ua, cred = _http(payload)
            r.update(proto="HTTP", http_method=method, http_uri=uri, http_host=host, http_user_agent=ua,
                     info=f"HTTP {method} {host}{uri}")
            if cred:
                r.update(cred_proto="HTTP Basic", cred_user=cred[0],
                         info=f"HTTP {method} {host}{uri} Authorization: Basic user={cred[0]} pass={cred[1]}")
            elif method == "POST":
                body = payload.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in payload else b""
                form = _form_creds(body)
                if form:
                    r.update(cred_proto="HTTP form", cred_user=form[0],
                             info=f"HTTP POST {host}{uri} form login user={form[0]} pass={form[1]}")
                elif not body:
                    pending_posts[flow] = f"{host}{uri}"   # body follows in the next packet of this connection
        elif flow in pending_posts and payload:
            target = pending_posts.pop(flow)
            form = _form_creds(payload)
            if form:
                r.update(proto="HTTP", cred_proto="HTTP form", cred_user=form[0],
                         info=f"HTTP POST body {target} form login user={form[0]} pass={form[1]}")
        elif payload.startswith(b"HTTP/") and not r["signature"]:
            head, _, body = payload.partition(b"\r\n\r\n")
            if any(b"content-type: " + ct in head.lower() for ct in EXE_TYPES) or PE_START_RE.match(body):
                r.update(signature="pe_file", info=f"HTTP response carrying a Windows executable -> {ip.dst}")
            elif not body:
                pending_bodies.add(flow)              # the file starts in the next packet of this connection
        elif flow in pending_bodies and payload:
            pending_bodies.discard(flow)
            if PE_START_RE.match(payload):
                r.update(signature="pe_file", info=f"HTTP response carrying a Windows executable -> {ip.dst}")
        elif t.dport == 21 and payload[:5].upper() in (b"USER ", b"PASS "):
            cmd, arg = payload[:4].decode().upper(), payload[5:].strip().decode("latin-1")
            r.update(proto="FTP", cred_proto="FTP", cred_user=arg if cmd == "USER" else "",
                     info=f"FTP {cmd} {arg if cmd == 'USER' else mask(arg)}")
    elif UDP in pkt:
        u = pkt[UDP]
        r.update(proto="UDP", src_port=u.sport, dst_port=u.dport, info=f"UDP {u.sport} -> {u.dport}")
        if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
            q = pkt[DNSQR].qname.decode("latin-1").rstrip(".")
            r.update(proto="DNS", dns_query=q, info=f"DNS query {q}")
    elif ICMP in pkt:
        r.update(proto="ICMP", info=f"ICMP type {pkt[ICMP].type}")
    else:
        r.update(proto=str(ip.payload.name), info=ip.payload.name)
    return r


def parse_pcap(data: bytes, max_packets=MAX_PACKETS) -> pd.DataFrame:
    """Bytes of a .pcap/.pcapng file -> one row per IP packet, sorted by time. Bad input -> empty frame."""
    rows, pending_posts, pending_bodies = [], {}, set()
    try:
        for i, pkt in enumerate(PcapReader(io.BytesIO(data))):
            if i >= max_packets:
                break
            r = _row(pkt, pending_posts, pending_bodies)
            if r:
                rows.append(r)
    except Exception:  # truncated or corrupt capture: keep what was read
        pass
    df = pd.DataFrame(rows, columns=COLUMNS)
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")
    df["src_port"] = df["src_port"].astype(int)
    df["dst_port"] = df["dst_port"].astype(int)
    df["host"], df["user"], df["event_type"] = df["dst_ip"], df["cred_user"], df["proto"]
    df["source_log"], df["detail"] = "pcap", df["info"]
    return df.sort_values("timestamp").reset_index(drop=True)
