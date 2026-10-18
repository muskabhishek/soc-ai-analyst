# Detections in Splunk SPL and Microsoft Sentinel KQL

Each of the 10 Python rules in [`src/detector.py`](../src/detector.py) is also written for the two most common
enterprise SIEMs, so the same detection logic can be deployed where a SOC already works.

| # | Rule | MITRE ATT&CK | Data source | Splunk | Sentinel |
|---|---|---|---|---|---|
| 1 | Brute force | T1110.001 | SSH auth log, Windows 4625 | [SPL](splunk/01_brute_force.spl) | [KQL](sentinel/01_brute_force.kql) |
| 2 | Password spraying | T1110.003 | SSH auth log | [SPL](splunk/02_password_spraying.spl) | [KQL](sentinel/02_password_spraying.kql) |
| 3 | Success after failures | T1078 | SSH auth log, Windows 4625 + 4624 | [SPL](splunk/03_success_after_failures.spl) | [KQL](sentinel/03_success_after_failures.kql) |
| 4 | Invalid user probing | T1087.001 | SSH auth log | [SPL](splunk/04_invalid_user_probing.spl) | [KQL](sentinel/04_invalid_user_probing.kql) |
| 5 | Odd-hour login | T1078 | SSH auth log, Windows 4624 | [SPL](splunk/05_odd_hour_login.spl) | [KQL](sentinel/05_odd_hour_login.kql) |
| 6 | New account created | T1136.001 | Windows 4720 | [SPL](splunk/06_new_account_created.spl) | [KQL](sentinel/06_new_account_created.kql) |
| 7 | Added to privileged group | T1098 | Windows 4732 / 4728 / 4756 | [SPL](splunk/07_admin_group_add.spl) | [KQL](sentinel/07_admin_group_add.kql) |
| 8 | Account lockout | T1110 | Windows 4740 | [SPL](splunk/08_account_lockout.spl) | [KQL](sentinel/08_account_lockout.kql) |
| 9 | Suspicious PowerShell | T1059.001 | Windows 4688 | [SPL](splunk/09_suspicious_powershell.spl) | [KQL](sentinel/09_suspicious_powershell.kql) |
| 10 | Audit log cleared | T1070.001 | Windows 1102 | [SPL](splunk/10_audit_log_cleared.spl) | [KQL](sentinel/10_audit_log_cleared.kql) |

Thresholds match `CONFIG` in `src/detector.py`, so a result in the Python tool should also appear in the SIEM.

## Assumptions about field names

**Splunk**
- Linux: `index=linux sourcetype=linux_secure`; user and IP are extracted with `rex`, so no add-on is needed.
- Windows: `index=wineventlog` with the Splunk Add-on for Microsoft Windows, which provides CIM fields
  (`src_ip`, `user`, `src_user`, `Group_Name`, `Process_Command_Line`). Change the index names to match your environment.
- `streamstats time_window=...` gives a true sliding window, the same method the Python engine uses.

**Microsoft Sentinel**
- Windows: the `SecurityEvent` table (Azure Monitor Agent / Windows Security Events connector).
- Linux: the `Syslog` table with the `auth`/`authpriv` facility collected.
- KQL `bin()` uses fixed time buckets, so an attack split across two buckets can be missed. Lower the threshold or
  use a rolling `row_window_session()` / join if that matters.

## Data-source prerequisites

- **4688 command lines** are only logged when *Audit Process Creation* is on **and** the policy
  *Include command line in process creation events* is enabled.
- **4720 / 4732 / 4740** need *Audit User Account Management* and *Audit Security Group Management*.
- **1102** is always logged when the Security log is cleared.

## Status

These queries are written to match the Python rules one for one and use the documented field names of each
platform. They have **not** yet been run against a live Splunk or Sentinel instance. Before relying on them,
run each one over a test dataset (for example Splunk's free *Boss of the SOC* data, or a Sentinel trial
workspace) and tune the thresholds.
