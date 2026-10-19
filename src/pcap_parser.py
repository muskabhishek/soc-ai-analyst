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
           "dns_query", "http_method", "http_host", "http_uri", "http_user_agent", "cred_proto", "cred_user", "info",
           # common-schema columns so captures are stored next to log events in the database
           "host", "user", "event_type", "status", "source_log", "detail"]

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")
BASIC_RE = re.compile(rb"^authorization:\s*basic\s+([A-Za-z0-9+/=]+)", re.I | re.M)


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


def _row(pkt):
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
        if payload.startswith(HTTP_METHODS):
            method, uri, host, ua, cred = _http(payload)
            r.update(proto="HTTP", http_method=method, http_uri=uri, http_host=host, http_user_agent=ua,
                     info=f"HTTP {method} {host}{uri}")
            if cred:
                r.update(cred_proto="HTTP Basic", cred_user=cred[0],
                         info=f"HTTP {method} {host}{uri} Authorization: Basic user={cred[0]} pass={cred[1]}")
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
    rows = []
    try:
        for i, pkt in enumerate(PcapReader(io.BytesIO(data))):
            if i >= max_packets:
                break
            r = _row(pkt)
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
