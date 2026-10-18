# Results on real data: SecRepo SSH auth.log

The pipeline was run, unchanged, on a real SSH log from an internet-facing AWS server
(SecRepo [auth.log](https://www.secrepo.com/auth.log/auth.log.gz), 30 Nov 2014 to 31 Dec 2014).
Reproduce with `python scripts/real_data_benchmark.py`.

## Headline numbers

| Measure | Value |
|---|---|
| Log lines read | 86,839 |
| Security events parsed | 14,825 |
| Processing time (parse + detect + score) | 10.4 s (8,315 lines/s) |
| Unique source IPs | 1,262 |
| Alerts raised | 236 (Medium: 234, High: 2) |
| Alerts by rule | invalid_user_probing: 234, brute_force: 2 |
| Distinct IPs alerted | 236 |
| Internal (RFC 1918) IPs alerted | 0 |
| Successful logins in the whole log | 0 |

## What the data showed

- **This server only accepts SSH keys.** There is not a single `Failed password` or `Accepted password` line, so the
  password-based rules (spraying, success after failures) correctly stay silent. Attacks appear as
  `Invalid user ...` (12,250 lines) and `Too many authentication failures for root` (2,575 lines).
- **The IP is missing on `Too many authentication failures` lines.** The parser recovers it from another line
  written by the same sshd process ID (for example the `reverse mapping ... [IP]` warning of that connection).
  That worked for 354 of 2,575 events; the other 2,221 had no such line
  (sshd logs the client IP for every connection only at `LogLevel VERBOSE`), so they are kept with source `unknown`
  instead of being dropped.
- **Root brute force from `unknown`:** 182 failed root sessions in 5 minutes on 2014-12-19 (07:09-07:14) raised a High alert.
- **Root brute force from `177.43.213.35`:** 27 failed root sessions in 5 minutes on 2014-12-17 (05:55-06:00) raised a High alert.
  Recommended hardening: `PermitRootLogin no`, `LogLevel VERBOSE`, and fail2ban to block repeat sources.
- **No internal addresses were alerted.** Every alert with a known source points at an external address, and there were no
  successful logins, so none of the alerts indicates a compromise. They are internet-wide scanning that a
  key-only configuration already blocks.
- **Low-and-slow scanners evade the threshold.** 1,260 IPs tried invalid usernames, but only 234 did
  it fast enough (5 in 10 minutes) to alert. 118 unflagged IPs still made 5 or more attempts
  in total, just spread out. A daily-count rule would catch them, at the cost of more alerts.

## Top 10 source IPs by invalid-user attempts

| Source IP | Attempts | Alerted |
|---|---|---|
| 218.25.17.234 | 409 | yes |
| 188.87.35.25 | 409 | yes |
| 61.197.203.243 | 409 | yes |
| 220.99.93.50 | 409 | yes |
| 123.57.51.31 | 360 | yes |
| 222.161.209.92 | 356 | yes |
| 173.192.158.3 | 303 | yes |
| 67.205.20.23 | 269 | yes |
| 78.129.223.28 | 269 | yes |
| 222.219.187.9 | 146 | yes |

## Top 10 usernames attackers tried

| Username | Attempts |
|---|---|
| admin | 1939 |
| test | 933 |
| guest | 515 |
| oracle | 449 |
| ftp | 418 |
| ftpuser | 392 |
| nagios | 340 |
| D-Link | 339 |
| debug | 335 |
| log | 327 |

These are default and service accounts (`admin`, `test`, `oracle`, `nagios`, ...): the reason to disable unused
default accounts and never allow password login for them.

## Busiest days

| Day | Events |
|---|---|
| 19 Dec 2014 | 1936 |
| 23 Dec 2014 | 1240 |
| 02 Dec 2014 | 1209 |
| 26 Dec 2014 | 1138 |
| 10 Dec 2014 | 951 |

## Limitations of this test

- There is no labelled ground truth for this log, so detection *rate* cannot be measured here; the planted-attack
  tests in `tests/` cover that. This run checks parsing on real formats, speed and false alarms on internal traffic.
- Syslog lines carry no year; the year is supplied on the command line.
