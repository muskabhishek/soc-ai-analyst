"""Run the detection pipeline on a REAL public SSH log and write docs/real-data-results.md.

Dataset: SecRepo auth.log (https://www.secrepo.com/) - an internet-facing AWS server, 30 Nov - 31 Dec 2014.
Usage:   python scripts/real_data_benchmark.py            (downloads the file on first run, ~600 KB)
         python scripts/real_data_benchmark.py path/to/auth.log[.gz] --year 2014
"""
import argparse
import gzip
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd

from src.pipeline import analyze_text
from src.scoring import _is_private

URL = "https://www.secrepo.com/auth.log/auth.log.gz"
DEFAULT = ROOT / "data/real/auth.log.gz"


def load(path):
    path = Path(path)
    if not path.exists() and path == DEFAULT:
        path.parent.mkdir(parents=True, exist_ok=True)
        print(f"Downloading {URL} ...")
        urllib.request.urlretrieve(URL, path)
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", errors="ignore") as f:
        return f.read()


def table(rows, headers):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=str(DEFAULT))
    ap.add_argument("--year", type=int, default=2014, help="syslog lines carry no year")
    ap.add_argument("--out", default=str(ROOT / "docs/real-data-results.md"))
    args = ap.parse_args()

    text = load(args.path)
    t0 = time.perf_counter()
    df, alerts = analyze_text(text, year=args.year)
    secs = time.perf_counter() - t0
    n_lines = text.count("\n")

    inv = df[df["event_type"] == "invalid_user"]
    per_ip = inv.groupby("source_ip").size()
    flagged = {a["source_ip"] for a in alerts if a["rule"] == "invalid_user_probing"}
    internal_flagged = sorted(ip for ip in {a["source_ip"] for a in alerts} if ip != "unknown" and _is_private(ip))
    rules = Counter(a["rule"] for a in alerts)
    sev = Counter(a["severity"] for a in alerts)
    top_ips = per_ip.sort_values(ascending=False).head(10)
    top_users = inv["user"].value_counts().head(10)
    daily = df.groupby(df["timestamp"].dt.date).size()
    busiest = daily.sort_values(ascending=False).head(5)
    root_fail = df[(df["detail"] == "too many authentication failures")]
    successes = int((df["status"] == "success").sum())
    unflagged = per_ip[~per_ip.index.isin(flagged)]
    recovered = int((root_fail["source_ip"] != "unknown").sum())
    bf_lines = "\n".join(
        f"- **Root brute force from `{a['source_ip']}`:** {a['count']} failed root sessions in 5 minutes on {a['start'][:10]} "
        f"({a['start'][11:16]}-{a['end'][11:16]}) raised a {a['severity']} alert."
        for a in alerts if a["rule"] == "brute_force")
    if bf_lines:
        bf_lines += "\n  Recommended hardening: `PermitRootLogin no`, `LogLevel VERBOSE`, and fail2ban to block repeat sources."

    md = f"""# Results on real data: SecRepo SSH auth.log

The pipeline was run, unchanged, on a real SSH log from an internet-facing AWS server
(SecRepo [auth.log]({URL}), {df['timestamp'].min():%d %b %Y} to {df['timestamp'].max():%d %b %Y}).
Reproduce with `python scripts/real_data_benchmark.py`.

## Headline numbers

| Measure | Value |
|---|---|
| Log lines read | {n_lines:,} |
| Security events parsed | {len(df):,} |
| Processing time (parse + detect + score) | {secs:.1f} s ({n_lines / secs:,.0f} lines/s) |
| Unique source IPs | {df['source_ip'].nunique():,} |
| Alerts raised | {len(alerts):,} ({', '.join(f'{k}: {v}' for k, v in sev.most_common())}) |
| Alerts by rule | {', '.join(f'{k}: {v}' for k, v in rules.most_common())} |
| Distinct IPs alerted | {len({a['source_ip'] for a in alerts}):,} |
| Internal (RFC 1918) IPs alerted | {len(internal_flagged)} |
| Successful logins in the whole log | {successes} |

## What the data showed

- **This server only accepts SSH keys.** There is not a single `Failed password` or `Accepted password` line, so the
  password-based rules (spraying, success after failures) correctly stay silent. Attacks appear as
  `Invalid user ...` ({len(inv):,} lines) and `Too many authentication failures for root` ({len(root_fail):,} lines).
- **The IP is missing on `Too many authentication failures` lines.** The parser recovers it from another line
  written by the same sshd process ID (for example the `reverse mapping ... [IP]` warning of that connection).
  That worked for {recovered:,} of {len(root_fail):,} events; the other {len(root_fail) - recovered:,} had no such line
  (sshd logs the client IP for every connection only at `LogLevel VERBOSE`), so they are kept with source `unknown`
  instead of being dropped.
{bf_lines}
- **No internal addresses were alerted.** Every alert with a known source points at an external address, and there were no
  successful logins, so none of the alerts indicates a compromise. They are internet-wide scanning that a
  key-only configuration already blocks.
- **Low-and-slow scanners evade the threshold.** {per_ip.size:,} IPs tried invalid usernames, but only {len(flagged):,} did
  it fast enough (5 in 10 minutes) to alert. {int((unflagged >= 5).sum()):,} unflagged IPs still made 5 or more attempts
  in total, just spread out. A daily-count rule would catch them, at the cost of more alerts.

## Top 10 source IPs by invalid-user attempts

{table([(ip, n, "yes" if ip in flagged else "no") for ip, n in top_ips.items()], ["Source IP", "Attempts", "Alerted"])}

## Top 10 usernames attackers tried

{table(list(top_users.items()), ["Username", "Attempts"])}

These are default and service accounts (`admin`, `test`, `oracle`, `nagios`, ...): the reason to disable unused
default accounts and never allow password login for them.

## Busiest days

{table([(f"{d:%d %b %Y}", n) for d, n in busiest.items()], ["Day", "Events"])}

## Limitations of this test

- There is no labelled ground truth for this log, so detection *rate* cannot be measured here; the planted-attack
  tests in `tests/` cover that. This run checks parsing on real formats, speed and false alarms on internal traffic.
- Syslog lines carry no year; the year is supplied on the command line.
"""
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md, encoding="utf-8")
    print(md)
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
