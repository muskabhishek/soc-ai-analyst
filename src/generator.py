"""Step 2 - Generate realistic sample logs (Linux auth.log + Windows events) with injected attacks."""
import base64
import csv
import io
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

USERS = ["alice", "bob", "carol", "dave", "sergio"]
NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "10.0.0.5"]
BASE = datetime(2026, 9, 28, 8, 0, 0)


def _ssh_line(ts, host, event, user, ip):
    t = ts.strftime("%b %d %H:%M:%S")
    pid = random.randint(1000, 9999)
    port = random.randint(30000, 60000)
    if event == "fail":
        return f"{t} {host} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"
    if event == "invalid":
        return f"{t} {host} sshd[{pid}]: Invalid user {user} from {ip} port {port}"
    return f"{t} {host} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"


def generate_linux_log(seed=42):
    """Returns (lines, ground_truth). Ground truth lists the attacks hidden in the log."""
    random.seed(seed)
    host, lines = "web-server-01", []
    for _ in range(120):  # normal working-hours traffic
        ts = BASE + timedelta(minutes=random.randint(0, 600))
        ev = "ok" if random.random() > 0.08 else "fail"
        lines.append((ts, _ssh_line(ts, host, ev, random.choice(USERS), random.choice(NORMAL_IPS))))
    # ATTACK 1: brute force on root, then success
    t0 = BASE + timedelta(hours=2)
    for i in range(35):
        ts = t0 + timedelta(seconds=i * 6)
        lines.append((ts, _ssh_line(ts, host, "fail", "root", "203.0.113.50")))
    ts = t0 + timedelta(seconds=230)
    lines.append((ts, _ssh_line(ts, host, "ok", "root", "203.0.113.50")))
    # ATTACK 2: password spraying
    t1 = BASE + timedelta(hours=5)
    for i, u in enumerate(["admin", "test", "oracle", "ubuntu", "postgres", "alice", "bob", "carol"]):
        ts = t1 + timedelta(seconds=i * 20)
        lines.append((ts, _ssh_line(ts, host, "fail", u, "198.51.100.7")))
    # ATTACK 3: invalid user probing
    t2 = BASE + timedelta(hours=7)
    for i, u in enumerate(["guest", "pi", "ftpuser", "git", "jenkins", "hadoop"]):
        ts = t2 + timedelta(seconds=i * 15)
        lines.append((ts, _ssh_line(ts, host, "invalid", u, "192.0.2.99")))
    # ATTACK 4: odd-hour login (3 AM)
    ts = datetime(2026, 9, 29, 3, 12, 0)
    lines.append((ts, _ssh_line(ts, host, "ok", "dave", "45.33.32.156")))
    lines.sort(key=lambda x: x[0])
    truth = {
        "brute_force": "203.0.113.50", "success_after_failures": "203.0.113.50",
        "password_spraying": "198.51.100.7", "invalid_user_probing": "192.0.2.99",
        "odd_hour_login": "45.33.32.156",
    }
    return [l for _, l in lines], truth


WIN_HEADER = "timestamp,host,event_id,user,ip,target_user,group,command_line"
BENIGN_PROCESSES = [
    r"C:\Windows\System32\svchost.exe -k netsvcs",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"powershell.exe -File C:\Scripts\backup.ps1",
    r"powershell.exe Get-Service",
    r"C:\Windows\System32\notepad.exe",
]


def _win_row(ts, host, eid, user, ip, target="", group="", cmd=""):
    buf = io.StringIO()
    csv.writer(buf, lineterminator="").writerow([f"{ts:%Y-%m-%d %H:%M:%S}", host, eid, user, ip, target, group, cmd])
    return ts, buf.getvalue()


def generate_windows_log(seed=7):
    """CSV-style Windows Security events (see WIN_HEADER) with a full attack chain hidden in normal activity."""
    random.seed(seed)
    host, rows = "WIN-DC01", []
    for _ in range(60):  # normal logons
        ts = BASE + timedelta(minutes=random.randint(0, 600))
        eid = 4624 if random.random() > 0.1 else 4625
        rows.append(_win_row(ts, host, eid, random.choice(USERS), random.choice(NORMAL_IPS)))
    for _ in range(20):  # normal process starts, incl. harmless PowerShell that must NOT alert
        ts = BASE + timedelta(minutes=random.randint(0, 600))
        rows.append(_win_row(ts, host, 4688, random.choice(USERS), random.choice(NORMAL_IPS),
                             cmd=random.choice(BENIGN_PROCESSES)))
    # benign: helpdesk adds a user to a non-privileged group (must NOT alert)
    rows.append(_win_row(BASE + timedelta(hours=1), host, 4732, "helpdesk", "192.168.1.10", "carol", "Print Operators"))

    # ATTACK CHAIN from 185.220.101.4: RDP brute force -> lockout -> break-in -> persistence -> execution -> cover-up
    ip, t0 = "185.220.101.4", BASE + timedelta(hours=4)
    for i in range(25):
        rows.append(_win_row(t0 + timedelta(seconds=i * 8), host, 4625, "administrator", ip))
    rows.append(_win_row(t0 + timedelta(seconds=205), host, 4740, "administrator", ip, target="administrator"))
    rows.append(_win_row(t0 + timedelta(seconds=260), host, 4624, "administrator", ip))
    rows.append(_win_row(t0 + timedelta(minutes=6), host, 4720, "administrator", ip, target="svc_update"))
    rows.append(_win_row(t0 + timedelta(minutes=7), host, 4732, "administrator", ip, "svc_update", "Administrators"))
    rows.append(_win_row(t0 + timedelta(minutes=9), host, 4688, "administrator", ip,
                         cmd="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="))
    rows.append(_win_row(t0 + timedelta(minutes=12), host, 1102, "administrator", ip))
    rows.sort(key=lambda x: x[0])
    truth = {"brute_force": ip, "account_lockout": ip, "success_after_failures": ip, "new_account_created": ip,
             "admin_group_add": ip, "suspicious_powershell": ip, "audit_log_cleared": ip}
    return [WIN_HEADER] + [r for _, r in rows], truth


def generate_pcap(path, seed=11):
    """Write a packet capture with normal traffic and hidden network attacks. Returns the ground truth as a set of
    (rule, source_ip). Packets are only written to a file, never sent. 203.0.113.50 is the same attacker as in
    auth.log, so the capture and the log can be correlated."""
    import logging
    logging.getLogger("scapy").setLevel(logging.ERROR)
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    random.seed(seed)
    t_base = BASE.replace(tzinfo=timezone.utc).timestamp()
    pkts = []

    def add(t, ip, l4, payload=b""):
        p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / ip / l4
        if payload:
            p = p / payload
        p.time = t_base + t
        pkts.append(p)

    def syn(t, src, dst, dport, sport=None, answer=None):
        sport = sport or random.randint(40000, 65000)
        add(t, IP(src=src, dst=dst), TCP(sport=sport, dport=dport, flags="S", seq=1000))
        if answer:
            add(t + 0.01, IP(src=dst, dst=src), TCP(sport=dport, dport=sport, flags=answer, seq=5000, ack=1001))
        return sport

    def tcp_send(t, src, dst, dport, data):
        sport = syn(t, src, dst, dport, answer="SA")
        add(t + 0.02, IP(src=src, dst=dst), TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=5001))
        add(t + 0.03, IP(src=src, dst=dst), TCP(sport=sport, dport=dport, flags="PA", seq=1001, ack=5001), data)

    def dns(t, src, name):
        add(t, IP(src=src, dst="10.0.0.2"), UDP(sport=random.randint(40000, 65000), dport=53) /
            DNS(id=random.randint(0, 65535), rd=1, qd=DNSQR(qname=name)))

    clients = ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14"]
    sites = {"www.google.com": "142.250.72.4", "api.github.com": "140.82.114.6", "outlook.office365.com": "52.97.1.10",
             "cdn.jsdelivr.net": "151.101.1.229", "www.wikipedia.org": "208.80.154.224"}
    for _ in range(150):  # normal browsing: DNS lookup, then HTTPS at irregular times
        t, c, (name, ip) = random.uniform(0, 36000), random.choice(clients), random.choice(list(sites.items()))
        dns(t, c, name)
        syn(t + 0.05, c, ip, 443, answer="SA")
    for _ in range(10):  # normal plain-HTTP page loads
        tcp_send(random.uniform(0, 36000), random.choice(clients), "93.184.216.34", 80,
                 b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
    for i in range(3):    # an admin's legitimate SSH sessions
        syn(1800 + i * 3600, "10.0.0.11", "10.0.0.20", 22, answer="SA")

    truth = set()
    atk = "203.0.113.50"  # ATTACK 1+2: port scan, then SSH brute force against the server
    for i, port in enumerate(range(1, 101)):
        syn(7000 + i * 0.1, atk, "10.0.0.20", port, sport=50000, answer="SA" if port in (22, 80) else "RA")
    for i in range(40):
        syn(7100 + i * 3, atk, "10.0.0.20", 22, answer="SA")
    truth |= {("port_scan", atk), ("net_brute_force", atk)}

    # ATTACK 3: cleartext credentials (FTP login, and HTTP Basic auth to a camera admin page)
    tcp_send(9000, "10.0.0.15", "203.0.113.80", 21, b"USER bob\r\n")
    tcp_send(9001, "10.0.0.15", "203.0.113.80", 21, b"PASS Winter2026!\r\n")
    tcp_send(9500, "10.0.0.16", "198.51.100.80", 80, b"GET /admin HTTP/1.1\r\nHost: camera.example\r\n"
             b"Authorization: Basic " + base64.b64encode(b"admin:admin123") + b"\r\n\r\n")
    truth |= {("cleartext_credentials", "10.0.0.15"), ("cleartext_credentials", "10.0.0.16")}

    # ATTACK 4: DNS tunnelling - data hidden in long random subdomains
    for i in range(15):
        label = "".join(random.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(45))
        dns(11000 + i * 2, "10.0.0.25", f"{label}.t.exfil-tunnel.example")
    truth.add(("suspicious_dns", "10.0.0.25"))

    # ATTACK 5: beaconing - an infected host checks in every 60 s (+/- 0.5 s)
    for i in range(20):
        syn(13000 + i * 60 + random.uniform(-0.5, 0.5), "10.0.0.30", "185.199.110.9", 443, answer="SA")
    truth.add(("beaconing", "10.0.0.30"))

    # ATTACK 6+7: executable downloaded over HTTP, then a connection to a Metasploit-style port
    tcp_send(15000, "10.0.0.31", "203.0.113.99", 80,
             b"GET /files/invoice.exe HTTP/1.1\r\nHost: cdn-update.example\r\nUser-Agent: Microsoft BITS/7.8\r\n\r\n")
    syn(15060, "10.0.0.31", "203.0.113.99", 4444, answer="SA")
    truth |= {("suspicious_download", "10.0.0.31"), ("suspicious_port", "10.0.0.31")}

    # ATTACK 7b: an executable disguised as an image - only the file header gives it away
    sport = syn(15500, "10.0.0.32", "203.0.113.98", 80, answer="SA")
    add(15500.05, IP(src="10.0.0.32", dst="203.0.113.98"), TCP(sport=sport, dport=80, flags="PA", seq=1001, ack=5001),
        b"GET /images/logo.jpg HTTP/1.1\r\nHost: static-cdn.example\r\n\r\n")
    add(15500.10, IP(src="203.0.113.98", dst="10.0.0.32"), TCP(sport=80, dport=sport, flags="PA", seq=5001, ack=1050),
        b"HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\n\r\n")
    add(15500.15, IP(src="203.0.113.98", dst="10.0.0.32"), TCP(sport=80, dport=sport, flags="PA", seq=5050, ack=1050),
        b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x00" * 50 + b"This program cannot be run in DOS mode.")
    truth.add(("suspicious_download", "10.0.0.32"))

    # ATTACK 8: login form posted over plain HTTP (credentials in the POST body)
    tcp_send(16000, "10.0.0.17", "203.0.113.81", 80, b"POST /login.php HTTP/1.1\r\nHost: portal.example\r\n"
             b"Content-Type: application/x-www-form-urlencoded\r\n\r\nusername=carol&password=Summer2026&submit=Login")
    truth.add(("cleartext_credentials", "10.0.0.17"))

    # ATTACK 9+10: exploit delivers shellcode, then the victim opens a reverse shell back to the attacker
    victim, c2 = "10.0.0.40", "198.51.100.66"
    sport = syn(17000, victim, c2, 8080, answer="SA")
    add(17000.2, IP(src=c2, dst=victim), TCP(sport=8080, dport=sport, flags="PA", seq=5001, ack=1001),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n"
        b"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30")
    tcp_send(17005, victim, c2, 4321, b"Microsoft Windows [Version 10.0.19045.3803]\r\n"
             b"(c) Microsoft Corporation. All rights reserved.\r\n\r\nC:\\Users\\dave>")
    truth |= {("exploit_shellcode", c2), ("remote_shell", victim)}

    pkts.sort(key=lambda p: p.time)
    wrpcap(str(path), pkts)
    return truth


def write_samples(out_dir="data/sample_logs"):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    lin, t1 = generate_linux_log()
    win, t2 = generate_windows_log()
    (out / "auth.log").write_text("\n".join(lin) + "\n")
    (out / "windows_security.csv").write_text("\n".join(win) + "\n")
    t3 = generate_pcap(out / "capture.pcap")
    return {"linux": t1, "windows": t2, "pcap": sorted(t3)}


if __name__ == "__main__":
    print(write_samples())
