"""Step 7 - Ollama LLM layer. The LLM ONLY explains alerts that Python already detected."""
import json
import os
import re
import requests

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")

SYSTEM_PROMPT = """You are a Tier-1 SOC analyst writing for a security team.
RULES:
- Use ONLY the alert data provided. Never invent IP addresses, usernames, times, or events.
- You do NOT decide whether something is a threat; the detection engine already did. Explain and prioritise it.
- Be concise and practical. This is a DEFENSIVE report: recommend containment and hardening only.
Reply in Markdown with exactly these sections:
## Summary
## Evidence
## Likely Attack
## Severity Reasoning
## Recommended Actions"""


def alert_to_brief(alert, max_evidence=8):
    """Compact, structured version of an alert that goes into the prompt."""
    return {
        "rule": alert["rule"], "severity": alert["severity"], "risk_score": alert["risk_score"],
        "source_ip": alert["source_ip"], "host": alert["host"], "users_involved": alert["users"],
        "event_count": alert["count"], "first_seen": alert["start"], "last_seen": alert["end"],
        "mitre_attack": alert["mitre"], "detector_description": alert["description"],
        "sample_evidence": alert["evidence"][:max_evidence],
    }


def build_prompt(alert):
    return f"{SYSTEM_PROMPT}\n\nALERT DATA (JSON):\n{json.dumps(alert_to_brief(alert), indent=2, default=str)}\n\nWrite the incident analysis now."


def ollama_available(timeout=2):
    try:
        return requests.get(f"{OLLAMA_URL}/api/tags", timeout=timeout).ok
    except requests.RequestException:
        return False


def call_ollama(prompt, model=None, timeout=120):
    r = requests.post(f"{OLLAMA_URL}/api/generate",
                      json={"model": model or OLLAMA_MODEL, "prompt": prompt, "stream": False,
                            "options": {"temperature": 0.2}}, timeout=timeout)
    r.raise_for_status()
    return r.json()["response"].strip()


REMEDIATION = {
    "brute_force": ["Block the source IP at the firewall", "Enable account lockout / rate limiting (fail2ban)",
                    "Enforce key-based SSH auth and disable password login", "Review whether any attempt succeeded"],
    "password_spraying": ["Block the source IP", "Force password resets for targeted accounts",
                          "Enable MFA", "Check for successful logins from the same IP"],
    "success_after_failures": ["Treat the account as compromised: disable it and reset credentials",
                               "Terminate active sessions", "Review commands/files touched after login",
                               "Block the source IP and hunt for persistence"],
    "invalid_user_probing": ["Block the source IP", "Disable unused default accounts", "Monitor for follow-up attempts"],
    "odd_hour_login": ["Confirm with the user whether the login was legitimate",
                       "If not, disable the account and reset credentials", "Restrict SSH by IP allow-list / VPN"],
    "new_account_created": ["Confirm the account was created through an approved change request",
                            "If not, disable the new account and investigate the creator's session"],
    "admin_group_add": ["Verify the change with the account owner and IT change records",
                        "If unauthorised, remove the member from the group and reset its credentials",
                        "Review what the account did with admin rights"],
    "account_lockout": ["Check the failed logons that caused the lockout and their source",
                        "Contact the user before unlocking", "Block the source if it is external"],
    "suspicious_powershell": ["Decode the command line and identify what it downloads or runs",
                              "Isolate the host if the payload is malicious",
                              "Enable PowerShell script block logging (Event ID 4104)"],
    "port_scan": ["Block the scanning IP at the perimeter firewall", "Check which scanned ports answered (open services)",
                  "Watch the same IP for follow-up exploitation or brute force"],
    "net_brute_force": ["Block the source IP", "Check the target's auth logs for a successful login from it",
                        "Rate-limit or VPN-restrict the exposed login service"],
    "cleartext_credentials": ["Reset the exposed password immediately", "Replace FTP/HTTP Basic with SFTP/HTTPS",
                              "Check whether the credentials were used from another IP"],
    "suspicious_dns": ["Identify the process on the host making the queries", "Sinkhole or block the parent domain",
                       "Isolate the host if data exfiltration is confirmed"],
    "beaconing": ["Isolate the host and find the process making the connections",
                  "Block the destination IP/domain", "Check threat intel for the destination"],
    "suspicious_download": ["Find the downloaded file on the host and hash it (VirusTotal)",
                            "Quarantine the file and isolate the host if malicious", "Block the source domain"],
    "suspicious_port": ["Identify the process using the port on the host", "Block the destination",
                        "Check for a reverse shell or RAT and isolate the host"],
    "audit_log_cleared": ["Treat as a high-priority incident: logs are cleared to hide activity",
                          "Collect remaining evidence (SIEM copies, other hosts) and isolate the host",
                          "Restrict who holds the 'Manage auditing and security log' right"],
}


def template_report(alert):
    """Deterministic fallback used when Ollama is not running. Same sections as the LLM report."""
    m = alert["mitre"]
    acts = "\n".join(f"- {a}" for a in REMEDIATION.get(alert["rule"], ["Investigate manually"]))
    return f"""## Summary
{alert['description']}

## Evidence
- Source IP: `{alert['source_ip']}` on host `{alert['host']}`
- Events: {alert['count']} between {alert['start']} and {alert['end']}
- Users involved: {', '.join(alert['users'])}

## Likely Attack
{m['name']} (MITRE ATT&CK {m['id']}, tactic: {m['tactic']}).

## Severity Reasoning
Risk score {alert['risk_score']}/100 ({alert['severity']}), based on rule type, number of attempts, source IP type and correlated activity.

## Recommended Actions
{acts}
"""


def check_hallucination(text, alert):
    """Flag any IP in the LLM text that is not present in the alert evidence."""
    known = {alert["source_ip"]} | {str(e.get("source_ip")) for e in alert["evidence"]}
    found = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text))
    return sorted(found - known)


def explain_alert(alert, use_llm=True, model=None):
    """Returns {'text', 'source', 'warnings'}. Falls back to the template if Ollama is unreachable."""
    if use_llm and ollama_available():
        try:
            text = call_ollama(build_prompt(alert), model=model)
            bad = check_hallucination(text, alert)
            warn = [f"LLM mentioned IPs not in the evidence: {', '.join(bad)} - verify manually."] if bad else []
            return {"text": text, "source": f"ollama:{model or OLLAMA_MODEL}", "warnings": warn}
        except Exception as e:  # network/model errors -> fallback
            return {"text": template_report(alert), "source": "template-fallback", "warnings": [f"Ollama error: {e}"]}
    return {"text": template_report(alert), "source": "template-fallback", "warnings": []}


def incident_report(alerts, explanations, title="Incident Report"):
    """Combine all alerts + explanations into one Markdown incident report."""
    lines = [f"# {title}", "", f"**Total alerts:** {len(alerts)}", ""]
    counts = {}
    for a in alerts:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1
    lines.append("**By severity:** " + ", ".join(f"{k}: {v}" for k, v in counts.items()) + "\n")
    for a in alerts:
        ex = explanations.get(a["alert_id"], {"text": "_No analysis generated._", "source": "-", "warnings": []})
        lines += [f"---\n\n# Alert {a['alert_id']}: {a['rule'].replace('_', ' ').title()} - {a['severity']} ({a['risk_score']})",
                  f"*MITRE: {a['mitre']['id']} {a['mitre']['name']} | Source: {ex['source']}*", "", ex["text"], ""]
        lines += [f"> WARNING: {w}" for w in ex["warnings"]]
    return "\n".join(lines)
