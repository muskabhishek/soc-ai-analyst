"""Triage playbooks: the written method an L1 analyst follows to reach a True / False Positive verdict.

Each rule has a YAML playbook in playbooks/ (the static, human-readable part). This module loads them and connects
them to live alerts: it pre-fills the 5 Ws (Who, What, When, Where, Why, How) from the alert's own fields, lists
evidence signals that lean towards True or False Positive, suggests a verdict, and drafts the closing comment.
The analyst always makes the final call.
"""
import string
from datetime import datetime
from functools import lru_cache
from pathlib import Path

import yaml

from .scoring import OUTBOUND_RULES, _is_private

PLAYBOOK_DIR = Path(__file__).resolve().parent.parent / "playbooks"
FIVE_WS = ["who", "what", "when", "where", "why", "how"]
W_LABELS = {"who": "Who", "what": "What", "when": "When", "where": "Where", "why": "Why", "how": "How"}
PRIVILEGED = {"root", "administrator", "admin", "system", "nt authority\\system", "domain admins", "sa"}
REQUIRED = {"rule", "title", "summary", "why_attackers", "five_ws", "true_positive_signs", "false_positive_signs",
            "investigate", "verdict_guide", "comment_template", "next_steps", "base_signal"}


@lru_cache(maxsize=1)
def load_playbooks():
    """rule -> playbook dict, read once from playbooks/*.yaml (files starting with '_' are not rule playbooks)."""
    books = {}
    for path in sorted(PLAYBOOK_DIR.glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        pb = yaml.safe_load(path.read_text(encoding="utf-8"))
        missing = REQUIRED - set(pb)
        if missing:
            raise ValueError(f"{path.name} is missing {sorted(missing)}")
        books[pb["rule"]] = pb
    return books


def get_playbook(rule):
    return load_playbooks().get(rule)


def method_guide():
    """The general triage method (playbooks/_method.md), shown before the rule playbooks."""
    path = PLAYBOOK_DIR / "_method.md"
    return path.read_text(encoding="utf-8") if path.exists() else ""


class _Blank(dict):
    def __missing__(self, key):
        return "?"


def _ip_type(ip):
    if not ip or ip in ("unknown", "-"):
        return "source not recorded"
    return "internal" if _is_private(ip) else "external"


def _duration(start, end):
    try:
        secs = int((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds())
    except (TypeError, ValueError):
        return "?"
    if secs < 60:
        return f"{secs} s"
    return f"{secs // 60} min {secs % 60} s" if secs < 3600 else f"{secs / 3600:.1f} h"


def alert_context(alert, related_alerts=()):
    """Plain values an analyst would read off the alert, used to fill playbook templates."""
    users = [u for u in alert.get("users") or [] if u]
    others = sorted({a["rule"] for a in related_alerts
                     if a.get("source_ip") == alert.get("source_ip") and a.get("rule") != alert.get("rule")})
    start, end = str(alert.get("start", "")), str(alert.get("end", ""))
    hour = start[11:13]
    mitre = alert.get("mitre") or {}
    return _Blank(
        rule=alert.get("rule", "?"), source_ip=alert.get("source_ip", "?"), ip_type=_ip_type(alert.get("source_ip")),
        peer_ip=alert.get("peer_ip") or "-", peer_type=_ip_type(alert.get("peer_ip")), host=alert.get("host", "?"),
        users=", ".join(users[:8]) or "no account recorded", user_count=len(users), count=alert.get("count", "?"),
        start=start, end=end, start_time=start[11:19] or "?", date=start[:10] or "?", duration=_duration(start, end),
        hour=hour or "?", description=alert.get("description", ""), mitre_id=mitre.get("id", "?"),
        mitre_name=mitre.get("name", "?"), tactic=mitre.get("tactic", "?"), severity=alert.get("severity", "?"),
        risk_score=alert.get("risk_score", "?"), wireshark_filter=alert.get("wireshark_filter") or "-",
        related_rules=", ".join(others) or "none", source="packet capture" if alert.get("peer_ip") is not None
        or alert.get("data_source") == "pcap" else "log file",
    )


def _fill(template, ctx):
    return string.Formatter().vformat(str(template or ""), (), ctx).strip()


def fill_five_ws(playbook, alert, related_alerts=()):
    """{w: {'ask': question for the analyst, 'auto': answer pre-filled from the alert ('' = analyst must answer)}}"""
    ctx = alert_context(alert, related_alerts)
    return {w: {"ask": playbook["five_ws"][w]["ask"], "auto": _fill(playbook["five_ws"][w].get("auto"), ctx)}
            for w in FIVE_WS}


def evidence_signals(playbook, alert, related_alerts=()):
    """[(text, lean)] with lean 'TP', 'FP' or 'info': facts that push the verdict one way or the other."""
    ctx = alert_context(alert, related_alerts)
    rule = alert.get("rule")
    signals = [(_fill(playbook["base_signal"]["text"], ctx), playbook["base_signal"]["lean"])]
    # where the alert came from; for outbound rules the internal host is the victim, so judge the other side
    side_ip = alert.get("peer_ip") if rule in OUTBOUND_RULES and alert.get("peer_ip") else alert.get("source_ip")
    side = _ip_type(side_ip)
    who = "Destination" if side_ip != alert.get("source_ip") else "Source"
    if side == "external":
        signals.append((f"{who} {side_ip} is on the internet, not a known internal system", "TP"))
    elif side == "internal":
        signals.append((f"{who} {side_ip} is internal: check whether it is an admin host, scanner or IT script", "FP"))
    else:
        signals.append(("Source IP was not recorded: use other evidence (host, time, other logs)", "info"))
    users = {u.lower() for u in alert.get("users") or []}
    if users & PRIVILEGED:
        signals.append((f"Privileged account involved ({', '.join(sorted(users & PRIVILEGED))})", "TP"))
    if ctx["related_rules"] != "none":
        signals.append((f"Same IP also triggered: {ctx['related_rules']}", "TP"))
    if ctx["hour"].isdigit() and int(ctx["hour"]) < 5:
        signals.append((f"Activity at {ctx['start_time']}, outside normal working hours", "TP"))
    return signals


def suggest_verdict(signals):
    """A suggestion from the signals, never a decision: (label, explanation)."""
    tp = sum(lean == "TP" for _, lean in signals)
    fp = sum(lean == "FP" for _, lean in signals)
    if tp >= 2 and fp == 0:
        return "Likely True Positive", f"{tp} signals point to an attack and none to benign activity."
    if fp > tp:
        return "Possibly False Positive", f"{fp} signals point to benign activity. Confirm the Why before closing."
    return "Analyst judgement needed", f"Signals are mixed ({tp} towards True Positive, {fp} towards False Positive)."


def draft_comment(playbook, alert, answers=None, verdict="", related_alerts=()):
    """Closing comment in the house style: facts, reasoning, verdict, next step. answers override the auto 5 Ws."""
    ctx = alert_context(alert, related_alerts)
    auto = fill_five_ws(playbook, alert, related_alerts)
    for w in FIVE_WS:
        ctx[w] = ((answers or {}).get(w) or auto[w]["auto"] or "").strip() or "not yet established"
    ctx["verdict"] = verdict or "pending analyst verdict"
    return _fill(playbook["comment_template"], ctx)


def worksheet_note(worksheet):
    """Readable text version of a saved worksheet, used in the case timeline and reports."""
    lines = ["5W triage worksheet"]
    lines += [f"{W_LABELS[w]}: {worksheet.get('answers', {}).get(w, '').strip() or '-'}" for w in FIVE_WS]
    if worksheet.get("verdict"):
        lines.append(f"Verdict: {worksheet['verdict']}")
    if worksheet.get("comment"):
        lines.append(f"Comment: {worksheet['comment']}")
    return "\n".join(lines)
