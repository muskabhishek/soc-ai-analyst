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


def test_windows_brute_force():
    lines, truth = generate_windows_log()
    _, alerts = analyze_text("\n".join(lines))
    assert _rules(alerts) == {("brute_force", truth["brute_force"])}


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
