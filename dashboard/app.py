"""Step 9 - Streamlit analyst dashboard.  Run:  streamlit run dashboard/app.py"""
import hashlib
import html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src import db
from src.llm import OLLAMA_MODEL, explain_alert, incident_report, ollama_available
from src.pipeline import analyze_text

st.set_page_config(page_title="AI SOC Analyst", page_icon="🛡️", layout="wide")
db.init_db()

SEV_COLORS = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e"}
SEV_DOTS = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
SEV_ORDER = ["Critical", "High", "Medium", "Low"]

st.markdown("""<style>
.block-container {padding-top: 1.6rem; max-width: 1400px;}
.hero {background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 55%, #0e7490 100%); border: 1px solid rgba(148,163,184,.25);
       border-radius: 16px; padding: 22px 28px; margin-bottom: 18px;}
.hero h1 {color: #f8fafc; font-size: 1.9rem; margin: 0; padding: 0; font-weight: 700;}
.hero p {color: #cbd5e1; margin: .35rem 0 0; font-size: .95rem;}
.hero .tags span {display: inline-block; margin: 12px 8px 0 0; padding: 3px 11px; border-radius: 999px; font-size: .75rem;
                  background: rgba(255,255,255,.08); color: #e2e8f0; border: 1px solid rgba(255,255,255,.16);}
.kpi {background: #111a2e; border: 1px solid #1f2a44; border-top: 3px solid var(--accent); border-radius: 14px; padding: 14px 18px;}
.kpi .label {color: #94a3b8; font-size: .74rem; text-transform: uppercase; letter-spacing: .07em;}
.kpi .value {color: #f8fafc; font-size: 1.9rem; font-weight: 700; line-height: 1.25; margin-top: 2px;}
.kpi .sub {color: #64748b; font-size: .76rem;}
.alert-card {background: #111a2e; border: 1px solid #1f2a44; border-left: 5px solid var(--sev); border-radius: 12px;
             padding: 16px 20px; margin: 6px 0 14px;}
.alert-card .head {display: flex; align-items: center; gap: 10px; flex-wrap: wrap;}
.alert-card .title {color: #f8fafc; font-size: 1.15rem; font-weight: 700;}
.pill {padding: 2px 10px; border-radius: 999px; font-size: .74rem; font-weight: 700; color: #0b1220; background: var(--sev);}
.alert-card .desc {color: #cbd5e1; margin: 8px 0 12px;}
.chips {display: flex; flex-wrap: wrap; gap: 8px;}
.chip {background: #0b1220; border: 1px solid #1f2a44; color: #94a3b8; border-radius: 8px; padding: 4px 10px; font-size: .8rem;}
.chip b {color: #f1f5f9; font-weight: 600;}
.score {margin-top: 14px; color: #94a3b8; font-size: .78rem;}
.score .bar {height: 8px; background: #1f2a44; border-radius: 999px; overflow: hidden; margin-top: 4px;}
.score .bar div {height: 100%; background: var(--sev); border-radius: 999px;}
.empty {text-align: center; padding: 48px 20px; border: 1px dashed #334155; border-radius: 16px; color: #94a3b8;}
.empty h3 {color: #e2e8f0; margin-bottom: 6px;}
</style>""", unsafe_allow_html=True)


def hero():
    st.markdown("""<div class="hero"><h1>🛡️ AI-Powered SOC Analyst</h1>
<p>Tier-1 triage for authentication logs: detect, classify, prioritise and report.</p>
<div class="tags"><span>Python detects</span><span>MITRE ATT&amp;CK classifies</span><span>Local LLM explains</span>
<span>Defensive use on your own logs only</span></div></div>""", unsafe_allow_html=True)


def kpi(col, label, value, sub, accent):
    col.markdown(f'<div class="kpi" style="--accent:{accent}"><div class="label">{label}</div>'
                 f'<div class="value">{value}</div><div class="sub">{sub}</div></div>', unsafe_allow_html=True)


def styled(fig, height=320):
    fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=height,
                      margin=dict(l=8, r=8, t=44, b=8), font=dict(color="#cbd5e1"),
                      title_font=dict(size=15, color="#f8fafc"), legend=dict(orientation="h", y=1.12, x=1, xanchor="right"))
    fig.update_xaxes(gridcolor="#1f2a44", zeroline=False)
    fig.update_yaxes(gridcolor="#1f2a44", zeroline=False)
    return fig


# ---------- sidebar ----------
with st.sidebar:
    st.markdown("### 🛡️ SOC Console")
    up = st.file_uploader("Upload a log file", type=["log", "txt", "csv"],
                          help="Linux SSH auth.log or Windows Security CSV (timestamp,host,event_id,user,ip)")
    use_sample = st.button("Use bundled sample log", width="stretch")
    st.divider()
    st.markdown("**AI explanations**")
    live = ollama_available()
    if live:
        st.success("Ollama is running", icon="🟢")
    else:
        st.warning("Ollama not running: template reports are used", icon="🟠")
    use_llm = st.toggle("Use LLM for explanations", value=live, disabled=not live)
    model = st.text_input("Model", OLLAMA_MODEL)

# ---------- analyse only when the input changes (so button clicks don't reset state) ----------
text, name = None, None
if up is not None:
    sig = hashlib.md5(up.getvalue()).hexdigest()
    if st.session_state.get("sig") != sig:
        text, name = up.getvalue().decode("utf-8", errors="ignore"), up.name
        st.session_state["sig"] = sig
elif use_sample:
    sample = Path(__file__).resolve().parent.parent / "data/sample_logs/auth.log"
    text, name = sample.read_text(), "auth.log (sample)"
    st.session_state["sig"] = "sample"

if text is not None:
    df, alerts = analyze_text(text)
    st.session_state.update(df=df, alerts=alerts, name=name, explanations={})
    st.session_state.pop("report", None)
    if not df.empty:
        db.save_analysis(name, df, alerts)

hero()

if "df" not in st.session_state:
    st.markdown("""<div class="empty"><h3>No log loaded yet</h3>
<p>Upload a Linux SSH <code>auth.log</code> or a Windows Security CSV in the sidebar,<br>
or click <b>Use bundled sample log</b> to see a demo with hidden attacks.</p></div>""", unsafe_allow_html=True)
    st.stop()

df, alerts = st.session_state["df"], st.session_state["alerts"]
if df.empty:
    st.error("No parsable events found in this file.")
    st.stop()

# ---------- KPI row ----------
fails = df[df["status"] == "failure"]
urgent = sum(a["severity"] in ("Critical", "High") for a in alerts)
k = st.columns(5)
kpi(k[0], "Events analysed", f"{len(df):,}", html.escape(st.session_state["name"]), "#3b82f6")
kpi(k[1], "Alerts", len(alerts), "rule matches", "#8b5cf6")
kpi(k[2], "Critical / High", urgent, "act on these first", SEV_COLORS["Critical"] if urgent else SEV_COLORS["Low"])
kpi(k[3], "Suspicious IPs", len({a["source_ip"] for a in alerts}), "unique sources in alerts", "#f97316")
kpi(k[4], "Failed logins", f"{len(fails):,}", f"{len(fails) / len(df):.0%} of all events", "#0ea5e9")
st.write("")

tab_overview, tab_alerts, tab_report = st.tabs(["📊 Overview", "🚨 Alerts & investigation", "📄 Incident report"])

# ---------- Overview ----------
with tab_overview:
    left, right = st.columns([2, 1])
    t = df.assign(bucket=df["timestamp"].dt.floor("15min"))
    t = t.groupby(["bucket", "status"]).size().reset_index(name="events")
    fig = px.bar(t, x="bucket", y="events", color="status", title="Activity over time (15-minute buckets)",
                 color_discrete_map={"failure": "#ef4444", "success": "#334155", "info": "#8b5cf6"},
                 labels={"bucket": "", "events": "events", "status": ""})
    left.plotly_chart(styled(fig), width="stretch")

    if alerts:
        sev = pd.Series([a["severity"] for a in alerts]).value_counts().reindex(SEV_ORDER).dropna()
        donut = go.Figure(go.Pie(labels=sev.index, values=sev.values, hole=.62, sort=False,
                                 marker=dict(colors=[SEV_COLORS[s] for s in sev.index], line=dict(color="#0b1220", width=2))))
        donut.update_layout(title="Alerts by severity", annotations=[dict(text=f"<b>{len(alerts)}</b><br>alerts",
                            showarrow=False, font=dict(size=18, color="#f8fafc"))])
        right.plotly_chart(styled(donut), width="stretch")

    left, right = st.columns(2)
    if not fails.empty:
        alert_ips = {a["source_ip"] for a in alerts}
        top = fails.groupby("source_ip").size().sort_values().tail(8)
        bars = go.Figure(go.Bar(x=top.values, y=top.index, orientation="h",
                                marker_color=["#ef4444" if ip in alert_ips else "#475569" for ip in top.index]))
        bars.update_layout(title="Top source IPs by failed logins (red = in an alert)")
        left.plotly_chart(styled(bars), width="stretch")
    if alerts:
        m = pd.Series([f"{a['mitre']['id']} {a['mitre']['name']}" for a in alerts]).value_counts().sort_values()
        mitre = go.Figure(go.Bar(x=m.values, y=m.index, orientation="h", marker_color="#8b5cf6"))
        mitre.update_layout(title="MITRE ATT&CK techniques observed")
        mitre.update_xaxes(dtick=1)
        right.plotly_chart(styled(mitre), width="stretch")

# ---------- Alerts ----------
with tab_alerts:
    if not alerts:
        st.success("No suspicious activity detected.")
    else:
        table = pd.DataFrame([{"ID": a["alert_id"], "Severity": f"{SEV_DOTS[a['severity']]} {a['severity']}",
                               "Risk score": a["risk_score"], "Rule": a["rule"].replace("_", " ").title(),
                               "Source IP": a["source_ip"], "Events": a["count"],
                               "MITRE": a["mitre"]["id"], "First seen": a["start"]} for a in alerts])
        st.dataframe(table, width="stretch", hide_index=True, column_config={
            "Risk score": st.column_config.ProgressColumn("Risk score", min_value=0, max_value=100, format="%.1f")})

        sel = st.selectbox("Investigate alert", [a["alert_id"] for a in alerts],
                           format_func=lambda i: next(f"#{i}  ·  {a['severity']}  ·  {a['rule'].replace('_', ' ').title()}"
                                                      f"  ·  {a['source_ip']}" for a in alerts if a["alert_id"] == i))
        a = next(x for x in alerts if x["alert_id"] == sel)
        e, m = html.escape, a["mitre"]
        users = ", ".join(a["users"][:6]) + (" …" if len(a["users"]) > 6 else "")
        st.markdown(f"""<div class="alert-card" style="--sev:{SEV_COLORS[a['severity']]}">
<div class="head"><span class="title">Alert #{a['alert_id']} · {e(a['rule'].replace('_', ' ').title())}</span>
<span class="pill">{a['severity']}</span></div>
<div class="desc">{e(a['description'])}</div>
<div class="chips"><span class="chip">Source IP <b>{e(a['source_ip'])}</b></span><span class="chip">Host <b>{e(a['host'])}</b></span>
<span class="chip">Events <b>{a['count']}</b></span><span class="chip">Window <b>{e(a['start'])} → {e(a['end'][11:])}</b></span>
<span class="chip">Users <b>{e(users)}</b></span><span class="chip">MITRE <b>{e(m['id'])} {e(m['name'])}</b></span>
<span class="chip">Tactic <b>{e(m['tactic'])}</b></span></div>
<div class="score">Risk score {a['risk_score']}/100<div class="bar"><div style="width:{a['risk_score']}%"></div></div></div>
</div>""", unsafe_allow_html=True)

        with st.expander(f"Evidence: {len(a['evidence'])} raw events"):
            st.dataframe(pd.DataFrame(a["evidence"]), width="stretch", hide_index=True)

        if st.button("✨ Generate analyst explanation", type="primary"):
            with st.spinner("Analysing..."):
                st.session_state["explanations"][sel] = explain_alert(a, use_llm=use_llm, model=model)
        ex = st.session_state["explanations"].get(sel)
        if ex:
            with st.container(border=True):
                st.caption(f"Source: {ex['source']}")
                st.markdown(ex["text"])
                for w in ex["warnings"]:
                    st.warning(w)

# ---------- Report ----------
with tab_report:
    if not alerts:
        st.info("Nothing to report: no alerts in this log.")
    else:
        st.write("Combine every alert and its explanation into one Markdown incident report for escalation.")
        if st.button("📄 Build full incident report", type="primary"):
            with st.spinner("Generating report for all alerts..."):
                for x in alerts:
                    st.session_state["explanations"].setdefault(x["alert_id"], explain_alert(x, use_llm=use_llm, model=model))
            st.session_state["report"] = incident_report(alerts, st.session_state["explanations"])
        if "report" in st.session_state:
            st.download_button("⬇ Download incident report (.md)", st.session_state["report"], "incident_report.md",
                               "text/markdown")
            with st.container(border=True, height=600):
                st.markdown(st.session_state["report"])
