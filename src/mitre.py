"""Step 5 - Map detection rules to MITRE ATT&CK techniques."""
MITRE_MAP = {
    "brute_force": {"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "password_spraying": {"id": "T1110.003", "name": "Brute Force: Password Spraying", "tactic": "Credential Access"},
    "success_after_failures": {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access / Persistence"},
    "invalid_user_probing": {"id": "T1087.001", "name": "Account Discovery: Local Account", "tactic": "Discovery"},
    "odd_hour_login": {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion / Persistence"},
    "new_account_created": {"id": "T1136.001", "name": "Create Account: Local Account", "tactic": "Persistence"},
    "admin_group_add": {"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence / Privilege Escalation"},
    "account_lockout": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "suspicious_powershell": {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution"},
    "audit_log_cleared": {"id": "T1070.001", "name": "Indicator Removal: Clear Windows Event Logs", "tactic": "Defense Evasion"},
}


def map_alert(alert):
    alert["mitre"] = MITRE_MAP.get(alert["rule"], {"id": "N/A", "name": "Unmapped", "tactic": "Unknown"})
    return alert


def map_alerts(alerts):
    return [map_alert(a) for a in alerts]
