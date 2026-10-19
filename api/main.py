"""Step 8b - FastAPI backend.  Run:  uvicorn api.main:app --reload   (docs at /docs)"""
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel
from src import db
from src.llm import explain_alert, ollama_available, incident_report
from src.pipeline import analyze_bytes

app = FastAPI(title="AI SOC Analyst", version="1.0")
db.init_db()


@app.get("/health")
def health():
    return {"status": "ok", "ollama": ollama_available()}


@app.post("/upload-logs")
async def upload_logs(file: UploadFile = File(...)):
    df, alerts, kind = analyze_bytes(await file.read())
    if df.empty:
        raise HTTPException(400, "No parsable events found (supported: Linux SSH auth.log, Windows security CSV, "
                                 "PCAP/PCAPNG packet captures).")
    upload_id, ids = db.save_analysis(file.filename, df, alerts)
    return {"upload_id": upload_id, "kind": kind, "events": len(df), "alerts": db.list_alerts(upload_id)}


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
