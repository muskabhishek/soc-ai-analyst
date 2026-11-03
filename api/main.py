"""Step 8b - FastAPI backend.  Run:  uvicorn api.main:app --reload   (docs at /docs)"""
import os
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from src import db
from src.llm import explain_alert, ollama_available, incident_report
from src.overview import build_overview
from src.pipeline import analyze_bytes

app = FastAPI(title="AI SOC Analyst", version="1.1")
# the Next.js web UI (web/) runs on another port during development
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
                   allow_methods=["*"], allow_headers=["*"])
db.init_db()
SAMPLES = {"auth": "auth.log", "windows": "windows_security.csv", "pcap": "capture.pcap"}
SAMPLE_DIR = Path(__file__).resolve().parent.parent / "data/sample_logs"


def _analyse_and_store(data: bytes, filename: str):
    df, alerts, kind = analyze_bytes(data)
    if df.empty:
        raise HTTPException(400, "No parsable events found (supported: Linux SSH auth.log, Windows security CSV, "
                                 "PCAP/PCAPNG packet captures).")
    upload_id, _ = db.save_analysis(filename, df, alerts, kind=kind, overview=build_overview(df, alerts, kind))
    return {"upload_id": upload_id, "kind": kind, "events": len(df), "alerts": db.list_alerts(upload_id)}


@app.get("/health")
def health():
    return {"status": "ok", "ollama": ollama_available()}


@app.post("/upload-logs")
async def upload_logs(file: UploadFile = File(...)):
    return _analyse_and_store(await file.read(), file.filename)


@app.post("/samples/{name}")
def load_sample(name: str):
    """Analyse one of the bundled sample files (auth, windows, pcap) as if it had been uploaded."""
    if name not in SAMPLES:
        raise HTTPException(404, f"Unknown sample; choose one of {sorted(SAMPLES)}")
    return _analyse_and_store((SAMPLE_DIR / SAMPLES[name]).read_bytes(), f"{SAMPLES[name]} (sample)")


@app.get("/uploads")
def uploads(limit: int = 50):
    return db.list_uploads(limit)


@app.get("/uploads/{upload_id}")
def upload(upload_id: int):
    """One upload: its chart summary (overview) and its alerts."""
    u = db.get_upload(upload_id)
    if not u:
        raise HTTPException(404, "Upload not found")
    return {**u, "alerts": db.list_alerts(upload_id)}


@app.get("/alerts")
def alerts(upload_id: int | None = None, status: str | None = None):
    return db.list_alerts(upload_id, status)


@app.get("/alerts/{alert_id}")
def alert_detail(alert_id: int):
    a = db.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    return a


@app.post("/alerts/{alert_id}/explain")
def explain(alert_id: int, use_llm: bool = True, model: str | None = None):
    a = db.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    ex = explain_alert(a, use_llm=use_llm, model=model)
    db.save_report(alert_id, ex["text"], ex["source"], ex["warnings"])
    return ex


@app.get("/stats")
def stats():
    return db.stats()


@app.get("/report/{upload_id}")
def report(upload_id: int):
    rows = db.list_alerts(upload_id)
    if not rows:
        raise HTTPException(404, "No alerts for this upload")
    full = [db.get_alert(r["id"]) for r in rows]
    exps = {}
    for i, a in enumerate(full, 1):
        a["alert_id"] = i
        exps[i] = a["report"] or explain_alert(a, use_llm=False)
    return {"markdown": incident_report(full, exps)}


# ---------------- case workflow ----------------

class StatusChange(BaseModel):
    status: str
    disposition: str | None = None
    note: str | None = None
    author: str = "analyst"


class Assignment(BaseModel):
    assignee: str
    author: str = "analyst"


class Note(BaseModel):
    text: str
    author: str = "analyst"


def _case_call(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except KeyError:
        raise HTTPException(404, "Alert not found")
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.patch("/alerts/{alert_id}/status")
def change_status(alert_id: int, body: StatusChange):
    _case_call(db.update_status, alert_id, body.status, body.author, body.disposition, body.note)
    return db.get_alert(alert_id)


@app.patch("/alerts/{alert_id}/assign")
def assign(alert_id: int, body: Assignment):
    _case_call(db.assign, alert_id, body.assignee, body.author)
    return db.get_alert(alert_id)


@app.post("/alerts/{alert_id}/notes")
def add_note(alert_id: int, body: Note):
    _case_call(db.add_note, alert_id, body.text, body.author)
    return db.get_activity(alert_id)


@app.get("/alerts/{alert_id}/activity")
def activity(alert_id: int):
    if not db.get_alert(alert_id):
        raise HTTPException(404, "Alert not found")
    return db.get_activity(alert_id)


@app.get("/metrics")
def metrics():
    """Queue by status, MTTA / MTTR in minutes, false-positive rate overall and per rule."""
    return db.case_metrics()


@app.get("/correlations")
def correlations():
    """IPs seen attacking in both log files and packet captures."""
    return db.correlations()


# ---------------- triage playbooks and 5W worksheets ----------------

class Worksheet(BaseModel):
    answers: dict[str, str] = {}
    verdict: str = ""
    comment: str = ""
    author: str = "analyst"


@app.get("/playbooks")
def playbooks():
    """All triage playbooks (one per detection rule)."""
    from src.playbooks import load_playbooks
    return [{"rule": r, "title": p["title"], "group": p["group"], "summary": p["summary"]}
            for r, p in load_playbooks().items()]


@app.get("/playbooks/{rule}")
def playbook(rule: str, alert_id: int | None = None):
    """A playbook; with ?alert_id it also returns the 5 Ws pre-filled from that alert, the evidence signals,
    a suggested verdict and a drafted closing comment."""
    from src import playbooks as pb
    book = pb.get_playbook(rule)
    if not book:
        raise HTTPException(404, "No playbook for this rule")
    if alert_id is None:
        return book
    a = db.get_alert(alert_id)
    if not a or a["rule"] != rule:
        raise HTTPException(404, "Alert not found for this playbook")
    related = db.list_alerts(a.get("upload_id")) if a.get("upload_id") else []   # other rules hit by the same IP
    signals = pb.evidence_signals(book, a, related)
    return {"playbook": book, "five_ws": pb.fill_five_ws(book, a, related), "signals": signals,
            "suggested_verdict": pb.suggest_verdict(signals), "draft_comment": pb.draft_comment(book, a, None, "",
                                                                                                  related)}


@app.get("/method")
def method():
    """The general triage method (Markdown)."""
    from src.playbooks import method_guide
    return {"markdown": method_guide()}


@app.get("/alerts/{alert_id}/worksheet")
def get_worksheet(alert_id: int):
    if not db.get_alert(alert_id):
        raise HTTPException(404, "Alert not found")
    return db.get_worksheet(alert_id) or {}


@app.put("/alerts/{alert_id}/worksheet")
def put_worksheet(alert_id: int, body: Worksheet):
    _case_call(db.save_worksheet, alert_id, body.model_dump(exclude={"author"}), body.author)
    return db.get_worksheet(alert_id)


class Triage(BaseModel):
    answers: dict[str, str] = {}
    verdict: str = ""            # "", "True Positive", "Benign True Positive" or "False Positive"
    comment: str = ""            # empty = drafted from the answers and verdict
    status: str = "In Progress"
    assignee: str = ""
    author: str = "analyst"


@app.post("/alerts/{alert_id}/triage")
def triage(alert_id: int, body: Triage):
    """Save the 5W worksheet and update the case (assignee, status, verdict) in one step."""
    from src import playbooks as pb
    a = db.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    if body.status == "Closed" and not body.verdict:
        raise HTTPException(422, "Pick a verdict before closing: True Positive, Benign True Positive or False Positive.")
    book = pb.get_playbook(a["rule"])
    related = db.list_alerts(a.get("upload_id")) if a.get("upload_id") else []
    comment = body.comment.strip() or (pb.draft_comment(book, a, body.answers, body.verdict, related) if book else "")
    db.save_worksheet(alert_id, {"answers": body.answers, "verdict": body.verdict, "comment": comment}, body.author)
    if body.assignee and body.assignee != (a.get("assignee") or ""):
        db.assign(alert_id, body.assignee, body.author)
    if body.status != a["status"] or (body.status == "Closed" and body.verdict != (a.get("disposition") or "")):
        _case_call(db.update_status, alert_id, body.status, body.author, body.verdict or None)
    return {"alert": db.get_alert(alert_id), "worksheet": db.get_worksheet(alert_id)}
