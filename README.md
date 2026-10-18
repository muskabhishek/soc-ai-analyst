# 🛡️ AI-Powered SOC Analyst & Threat Detection Assistant

A **defensive**, fully local tool that behaves like a Tier-1 SOC analyst: it parses security logs, detects
attacks with Python/Pandas, maps them to **MITRE ATT&CK**, scores the risk, and uses a local **Ollama** LLM to
explain each alert and write an incident report.

> **Design rule:** Python decides *what is a threat*. The LLM only *explains and prioritises*. It never decides
> threat status, and its output is checked for invented IP addresses.

## Architecture
```
Logs (Linux auth.log / Windows CSV)
   -> parser.py     common schema (Pandas)
   -> detector.py   rule-based detection (sliding time windows)
   -> mitre.py      ATT&CK technique mapping
   -> scoring.py    risk score -> Low/Medium/High/Critical
   -> llm.py        Ollama explanation + incident report (template fallback if Ollama is off)
   -> db.py         SQLite   <->  api/main.py (FastAPI)  <->  dashboard/app.py (Streamlit)
```

## Detection rules
| Rule | Logic | MITRE |
|---|---|---|
| Brute force | >=10 failed logins from one IP in 5 min | T1110.001 |
| Password spraying | one IP, >=5 distinct usernames in 10 min | T1110.003 |
| Success after failures | login succeeds after >=5 failures from same IP | T1078 |
| Invalid user probing | >=5 non-existent usernames from one IP | T1087.001 |
| Odd-hour login | successful login 00:00-05:00 | T1078 |
| New account created | Windows 4720 | T1136.001 |
| Added to privileged group | Windows 4732 into Administrators / Domain Admins / Enterprise Admins / Schema Admins | T1098 |
| Account lockout | Windows 4740 | T1110 |
| Suspicious PowerShell | Windows 4688 command line with `-enc`, `-w hidden`, `IEX`, `DownloadString`, `FromBase64String` | T1059.001 |
| Audit log cleared | Windows 1102 | T1070.001 |

Thresholds live in `CONFIG` at the top of `src/detector.py`.

## Quick start
```bash
pip install -r requirements.txt
python -m src.generator                 # create sample logs with hidden attacks
python -m pytest -q tests               # every injected attack found, no false positives

# optional: real LLM explanations
ollama serve & ollama pull llama3.2

uvicorn api.main:app --reload           # API  -> http://127.0.0.1:8000/docs
streamlit run dashboard/app.py          # UI   -> http://localhost:8501
```
Or step through everything in `notebooks/development.ipynb`.

Env vars: `OLLAMA_URL` (default `http://localhost:11434`), `OLLAMA_MODEL` (default `llama3.2`), `SOC_DB`.

## API
| Endpoint | Purpose |
|---|---|
| `POST /upload-logs` | upload + analyse a log file |
| `GET /alerts`, `GET /alerts/{id}` | list alerts / detail with report |
| `POST /alerts/{id}/explain` | generate (and store) LLM or template explanation |
| `GET /report/{upload_id}` | full Markdown incident report |
| `GET /stats`, `GET /health` | counters / Ollama status |

## Supported log formats
- Linux SSH `auth.log` (Failed password / Accepted password / Invalid user)
- Windows Security CSV: `timestamp,host,event_id,user,ip[,target_user,group,command_line]`
  - Event IDs: 4624 logon success, 4625 logon failure, 4720 account created, 4732 added to group,
    4740 account locked out, 4688 process created, 1102 audit log cleared
  - The sample Windows log hides a full attack chain: RDP brute force -> lockout -> break-in -> new account ->
    added to Administrators -> encoded PowerShell -> audit log cleared. Benign PowerShell and non-admin group
    changes are included to prove they do **not** alert.

Adding a format = one new function in `src/parser.py` returning the common schema.

## Ethics & scope
Defensive analysis only. Run it on logs and systems you own or are authorised to monitor.

## Stretch goals
Live log tailing, firewall-log correlation, offline GeoIP enrichment, Isolation Forest anomaly detection, PDF export.
