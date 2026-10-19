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
    # network (PCAP) rules
    "port_scan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "net_brute_force": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "cleartext_credentials": {"id": "T1040", "name": "Network Sniffing (credentials exposed in cleartext)", "tactic": "Credential Access"},
    "suspicious_dns": {"id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control / Exfiltration"},
    "beaconing": {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols (C2 beaconing)", "tactic": "Command and Control"},
    "suspicious_download": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "suspicious_port": {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
}


def map_alert(alert):
    alert["mitre"] = MITRE_MAP.get(alert["rule"], {"id": "N/A", "name": "Unmapped", "tactic": "Unknown"})
    return alert


def map_alerts(alerts):
    return [map_alert(a) for a in alerts]
