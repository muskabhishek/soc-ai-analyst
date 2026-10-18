"""Step 6 - Risk scoring: weighted score -> Low / Medium / High / Critical."""
import ipaddress

BASE = {"brute_force": 40, "password_spraying": 45, "success_after_failures": 65,
        "invalid_user_probing": 25, "odd_hour_login": 35}


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]


def _is_private(ip):
    """Internal = RFC1918 + loopback only (documentation ranges used in samples count as external)."""
    try:
        return any(ipaddress.ip_address(ip) in n for n in _INTERNAL)
    except ValueError:
        return False


def level(score):
    return "Critical" if score >= 80 else "High" if score >= 60 else "Medium" if score >= 35 else "Low"


def score_alerts(alerts):
    rules_per_ip = {}
    for a in alerts:
        rules_per_ip.setdefault(a["source_ip"], set()).add(a["rule"])
    for a in alerts:
        s = BASE.get(a["rule"], 20)
        s += min(a["count"] / 2, 20)                       # volume of attempts
        if len(rules_per_ip[a["source_ip"]]) >= 2:
            s += 15                                        # correlated behaviour from same IP
        if not _is_private(a["source_ip"]):
            s += 10                                        # external source
        else:
            s -= 10
        a["risk_score"] = round(max(0, min(100, s)), 1)
        a["severity"] = level(a["risk_score"])
    return sorted(alerts, key=lambda x: x["risk_score"], reverse=True)
