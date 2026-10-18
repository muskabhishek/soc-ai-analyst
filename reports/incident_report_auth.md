# Incident Report

**Total alerts:** 5

**By severity:** Critical: 2, Medium: 3

---

# Alert 1: Success After Failures - Critical (100)
*MITRE: T1078 Valid Accounts | Source: template-fallback*

## Summary
Successful login for 'root' from 203.0.113.50 right after 35 failed attempts - possible account compromise.

## Evidence
- Source IP: `203.0.113.50` on host `web-server-01`
- Events: 35 between 2026-09-28 10:00:00 and 2026-09-28 10:03:50
- Users involved: root

## Likely Attack
Valid Accounts (MITRE ATT&CK T1078, tactic: Initial Access / Persistence).

## Severity Reasoning
Risk score 100/100 (Critical), based on rule type, number of attempts, source IP type and correlated activity.

## Recommended Actions
- Treat the account as compromised: disable it and reset credentials
- Terminate active sessions
- Review commands/files touched after login
- Block the source IP and hunt for persistence


---

# Alert 2: Brute Force - Critical (82.5)
*MITRE: T1110.001 Brute Force: Password Guessing | Source: template-fallback*

## Summary
35 failed logins from 203.0.113.50 within 5 minutes (users targeted: 1).

## Evidence
- Source IP: `203.0.113.50` on host `web-server-01`
- Events: 35 between 2026-09-28 10:00:00 and 2026-09-28 10:03:24
- Users involved: root

## Likely Attack
Brute Force: Password Guessing (MITRE ATT&CK T1110.001, tactic: Credential Access).

## Severity Reasoning
Risk score 82.5/100 (Critical), based on rule type, number of attempts, source IP type and correlated activity.

## Recommended Actions
- Block the source IP at the firewall
- Enable account lockout / rate limiting (fail2ban)
- Enforce key-based SSH auth and disable password login
- Review whether any attempt succeeded


---

# Alert 3: Password Spraying - Medium (59.0)
*MITRE: T1110.003 Brute Force: Password Spraying | Source: template-fallback*

## Summary
198.51.100.7 attempted logins against 8 different usernames within 10 minutes.

## Evidence
- Source IP: `198.51.100.7` on host `web-server-01`
- Events: 8 between 2026-09-28 13:00:00 and 2026-09-28 13:02:20
- Users involved: admin, alice, bob, carol, oracle, postgres, test, ubuntu

## Likely Attack
Brute Force: Password Spraying (MITRE ATT&CK T1110.003, tactic: Credential Access).

## Severity Reasoning
Risk score 59.0/100 (Medium), based on rule type, number of attempts, source IP type and correlated activity.

## Recommended Actions
- Block the source IP
- Force password resets for targeted accounts
- Enable MFA
- Check for successful logins from the same IP


---

# Alert 4: Odd Hour Login - Medium (45.5)
*MITRE: T1078 Valid Accounts | Source: template-fallback*

## Summary
Successful login for 'dave' at 03:12 (outside normal hours) from 45.33.32.156.

## Evidence
- Source IP: `45.33.32.156` on host `web-server-01`
- Events: 1 between 2026-09-29 03:12:00 and 2026-09-29 03:12:00
- Users involved: dave

## Likely Attack
Valid Accounts (MITRE ATT&CK T1078, tactic: Defense Evasion / Persistence).

## Severity Reasoning
Risk score 45.5/100 (Medium), based on rule type, number of attempts, source IP type and correlated activity.

## Recommended Actions
- Confirm with the user whether the login was legitimate
- If not, disable the account and reset credentials
- Restrict SSH by IP allow-list / VPN


---

# Alert 5: Invalid User Probing - Medium (38.0)
*MITRE: T1087.001 Account Discovery: Local Account | Source: template-fallback*

## Summary
6 attempts with non-existent usernames from 192.0.2.99 - account enumeration.

## Evidence
- Source IP: `192.0.2.99` on host `web-server-01`
- Events: 6 between 2026-09-28 15:00:00 and 2026-09-28 15:01:15
- Users involved: ftpuser, git, guest, hadoop, jenkins, pi

## Likely Attack
Account Discovery: Local Account (MITRE ATT&CK T1087.001, tactic: Discovery).

## Severity Reasoning
Risk score 38.0/100 (Medium), based on rule type, number of attempts, source IP type and correlated activity.

## Recommended Actions
- Block the source IP
- Disable unused default accounts
- Monitor for follow-up attempts

