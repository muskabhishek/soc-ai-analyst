"""Step 9 - Streamlit analyst dashboard.  Run:  streamlit run dashboard/app.py"""
import hashlib
import html
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # project root, for src
sys.path.insert(0, str(Path(__file__).resolve().parent))          # dashboard/, for ui

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src import db
from src.llm import OLLAMA_MODEL, explain_alert, incident_report, ollama_available
from src.pipeline import analyze_bytes
from ui import SEV_COLORS, SEV_DOTS, SEV_ORDER, apply_style, hero, kpi, render_worksheet, styled

st.set_page_config(page_title="AI SOC Analyst", page_icon="🛡️", layout="wide")
db.init_db()

apply_style()


# ---------- sidebar ----------
with st.sidebar:
    st.markdown("### 🛡️ SOC Console")
    up = st.file_uploader("Upload a log file or packet capture", type=["log", "txt", "csv", "pcap", "pcapng", "cap"],
                          help="Linux SSH auth.log, Windows Security CSV, or a Wireshark .pcap / .pcapng capture")
    s1, s2 = st.columns(2)
    use_sample = s1.button("Sample log", width="stretch")
    use_pcap = s2.button("Sample PCAP", width="stretch")
    st.divider()
    st.markdown("**AI explanations**")
    live = ollama_available()
    if live:
        st.success("Ollama is running", icon="🟢")
    else:
        st.warning("Ollama not running: template reports are used", icon="🟠")
    use_llm = st.toggle("Use LLM for explanations", value=live, disabled=not live)
    model = st.text_input("Model", OLLAMA_MODEL)
    st.divider()
    analyst = st.text_input("Analyst name", st.session_state.get("analyst_name", "analyst1"),
                            help="Recorded on status changes, notes and worksheets")
    st.session_state["analyst_name"] = analyst
    st.page_link("pages/1_Triage_Playbook.py", label="Open the Triage Playbook", icon="📖")

# ---------- analyse only when the input changes (so button clicks don't reset state) ----------
SAMPLES = Path(__file__).resolve().parent.parent / "data/sample_logs"
data, name = None, None
if up is not None:
    sig = hashlib.md5(up.getvalue()).hexdigest()
    if st.session_state.get("sig") != sig:
        data, name = up.getvalue(), up.name
        st.session_state["sig"] = sig
elif use_sample or use_pcap or (st.query_params.get("sample") in ("auth", "pcap") and "sig" not in st.session_state):
    # ?sample=auth or ?sample=pcap in the URL opens the dashboard straight on a demo
    fname = "capture.pcap" if use_pcap or (not use_sample and st.query_params.get("sample") == "pcap") else "auth.log"
    data, name = (SAMPLES / fname).read_bytes(), f"{fname} (sample)"
    st.session_state["sig"] = fname

if data is not None:
    with st.spinner("Analysing..."):
        df, alerts, kind = analyze_bytes(data)
    st.session_state.update(df=df, alerts=alerts, name=name, kind=kind, explanations={})
    st.session_state.pop("report", None)
    st.session_state["db_ids"] = {}
    if not df.empty:
        upload_id, ids = db.save_analysis(name, df, alerts)
        st.session_state["db_ids"] = {a["alert_id"]: i for a, i in zip(alerts, ids)}

hero()

if "df" not in st.session_state:
    st.markdown("""<div class="empty"><h3>No data loaded yet</h3>
<p>Upload a Linux SSH <code>auth.log</code>, a Windows Security CSV or a Wireshark <code>.pcap</code> in the sidebar,<br>
or click <b>Sample log</b> / <b>Sample PCAP</b> to see a demo with hidden attacks.</p></div>""", unsafe_allow_html=True)
    st.stop()

df, alerts = st.session_state["df"], st.session_state["alerts"]
is_pcap = st.session_state.get("kind") == "pcap"
if df.empty:
    st.error("No parsable events found in this file.")
    st.stop()

# ---------- KPI row ----------
fails = df[df["status"] == "failure"]
urgent = sum(a["severity"] in ("Critical", "High") for a in alerts)
k = st.columns(5)
kpi(k[0], "Packets analysed" if is_pcap else "Events analysed", f"{len(df):,}", html.escape(st.session_state["name"]), "#3b82f6")
kpi(k[1], "Alerts", len(alerts), "rule matches", "#8b5cf6")
kpi(k[2], "Critical / High", urgent, "act on these first", SEV_COLORS["Critical"] if urgent else SEV_COLORS["Low"])
kpi(k[3], "Suspicious IPs", len({a["source_ip"] for a in alerts}), "unique sources in alerts", "#f97316")
if is_pcap:
    span = (df["timestamp"].max() - df["timestamp"].min()).total_seconds() / 3600
    kpi(k[4], "Hosts seen", f"{len(set(df['source_ip']) | set(df['dst_ip'])):,}", f"over {span:.1f} h of traffic", "#0ea5e9")
else:
    kpi(k[4], "Failed logins", f"{len(fails):,}", f"{len(fails) / len(df):.0%} of all events", "#0ea5e9")
st.write("")

tab_overview, tab_alerts, tab_cases, tab_report = st.tabs(
    ["📊 Overview", "🚨 Alerts & investigation", "🗂️ Case queue", "📄 Incident report"])
db_ids = st.session_state.get("db_ids", {})
case = {r["id"]: r for r in db.list_alerts()} if db_ids else {}

# ---------- Overview ----------
with tab_overview:
    left, right = st.columns([2, 1])
    t = df.assign(bucket=df["timestamp"].dt.floor("15min"))
    if is_pcap:
        t = t.groupby(["bucket", "proto"]).size().reset_index(name="packets")
        fig = px.bar(t, x="bucket", y="packets", color="proto", title="Packets over time by protocol (15-minute buckets)",
                     color_discrete_sequence=["#3b82f6", "#8b5cf6", "#0ea5e9", "#f97316", "#ef4444", "#22c55e"],
                     labels={"bucket": "", "proto": ""})
    else:
        t = t.groupby(["bucket", "status"]).size().reset_index(name="events")
        fig = px.bar(t, x="bucket", y="events", color="status", title="Activity over time (15-minute buckets)",
                     color_discrete_map={"failure": "#ef4444", "success": "#334155", "info": "#8b5cf6"},
                     labels={"bucket": "", "events": "events", "status": ""})
    left.plotly_chart(styled(fig), width="stretch")

    if alerts:
        sev = pd.Series([a["severity"] for a in alerts]).value_counts().reindex(SEV_ORDER).dropna()
        donut = go.Figure(go.Pie(labels=sev.index, values=sev.values, hole=.62, sort=False,
                                 marker=dict(colors=[SEV_COLORS[s] for s in sev.index], line=dict(color="#0b1220", width=2))))
        donut.update_layout(title="Alerts by severity", legend=dict(orientation="h", y=-0.08, x=0.5, xanchor="center"), annotations=[dict(text=f"<b>{len(alerts)}</b><br>alerts",
                            showarrow=False, font=dict(size=18, color="#f8fafc"))])
        right.plotly_chart(styled(donut).update_layout(legend=dict(orientation="h", y=-0.08, x=0.5, xanchor="center")),
                           width="stretch")

    left, right = st.columns(2)
    alert_ips = {a["source_ip"] for a in alerts}
    if is_pcap:
        top = df.groupby("source_ip").size().sort_values().tail(8)
        bars = go.Figure(go.Bar(x=top.values, y=top.index, orientation="h",
                                marker_color=["#ef4444" if ip in alert_ips else "#475569" for ip in top.index]))
        bars.update_layout(title="Top talkers by packets sent (red = in an alert)")
        left.plotly_chart(styled(bars), width="stretch")
    elif not fails.empty:
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

    if is_pcap:
        left, right = st.columns(2)
        ports = df[(df["flags"] == "S") & (df["dst_port"] > 0)].groupby("dst_port").size().sort_values().tail(10)
        pfig = go.Figure(go.Bar(x=ports.values, y=[str(p) for p in ports.index], orientation="h", marker_color="#0ea5e9"))
        pfig.update_layout(title="Most-contacted destination ports (new TCP connections)")
        pfig.update_yaxes(type="category")
        left.plotly_chart(styled(pfig), width="stretch")
        with right:
            st.markdown("##### DNS queries and HTTP requests")
            dns_tab, http_tab = st.tabs(["DNS", "HTTP"])
            dq = df[df["dns_query"] != ""]
            dns_tab.dataframe(dq.groupby(["source_ip", "dns_query"]).size().reset_index(name="queries")
                              .sort_values("queries", ascending=False), width="stretch", hide_index=True, height=300)
            hq = df[df["http_method"] != ""][["timestamp", "source_ip", "http_method", "http_host", "http_uri"]]
            http_tab.dataframe(hq, width="stretch", hide_index=True, height=300)

# ---------- Alerts ----------
with tab_alerts:
    if not alerts:
        st.success("No suspicious activity detected.")
    else:
        table = pd.DataFrame([{"ID": a["alert_id"], "Severity": f"{SEV_DOTS[a['severity']]} {a['severity']}",
                               "Risk score": a["risk_score"], "Rule": a["rule"].replace("_", " ").title(),
                               "Status": case.get(db_ids.get(a["alert_id"]), {}).get("status", "-"),
                               "Source IP": a["source_ip"], "Events": a["count"],
                               "MITRE": a["mitre"]["id"], "First seen": a["start"]} for a in alerts])
        st.dataframe(table, width="stretch", hide_index=True, column_config={
            "Risk score": st.column_config.ProgressColumn("Risk score", min_value=0, max_value=100, format="%.1f")})

        ids = [a["alert_id"] for a in alerts]
        focus = st.session_state.pop("focus_alert", None)          # set when coming back from the playbook page
        if focus in ids:
            st.session_state["investigate"] = focus
        sel = st.selectbox("Investigate alert", ids, key="investigate",
                           format_func=lambda i: next(f"#{i}  ·  {a['severity']}  ·  {a['rule'].replace('_', ' ').title()}"
                                                      f"  ·  {a['source_ip']}" for a in alerts if a["alert_id"] == i))
        a = next(x for x in alerts if x["alert_id"] == sel)
        e, m = html.escape, a["mitre"]
        users = (", ".join(a["users"][:6]) + (" …" if len(a["users"]) > 6 else "")) or "-"
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

        cid = db_ids.get(sel)
        if st.button(f"📖 Open the {a['rule'].replace('_', ' ')} playbook", help="How to decide True or False Positive "
                     "for this alert type, with the same 5W worksheet"):
            st.session_state.update(pb_rule=a["rule"], pb_alert=cid)
            st.switch_page("pages/1_Triage_Playbook.py")
        if a.get("wireshark_filter"):
            st.caption("Wireshark display filter: paste it into Wireshark's filter bar to see the evidence packets")
            st.code(a["wireshark_filter"], language=None)
        with st.expander(f"Evidence: {len(a['evidence'])} raw {'packets' if is_pcap else 'events'}"):
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

        # ----- triage: 5W worksheet, verdict and case update for the selected alert -----
        if cid:
            render_worksheet(a, cid, analyst, alerts, key="dash")

# ---------- Case queue ----------
with tab_cases:
    m = db.case_metrics()
    q = st.columns(5)
    kpi(q[0], "Open cases", m["open"], "New + In Progress + Escalated", "#3b82f6")
    kpi(q[1], "Escalated", m["by_status"]["Escalated"], "handed to L2 / IR", SEV_COLORS["High"])
    kpi(q[2], "MTTA", "-" if m["mtta_minutes"] is None else f"{m['mtta_minutes']} min", "mean time to acknowledge", "#8b5cf6")
    kpi(q[3], "MTTR", "-" if m["mttr_minutes"] is None else f"{m['mttr_minutes']} min", "mean time to resolve", "#0ea5e9")
    kpi(q[4], "False-positive rate", "-" if m["false_positive_rate_pct"] is None else f"{m['false_positive_rate_pct']}%",
        f"of {m['closed']} closed alerts", SEV_COLORS["Medium"])
    st.write("")
    corr = db.correlations()
    st.markdown("##### 🔗 Cross-source correlations")
    if corr:
        st.caption("These IPs attacked in BOTH log files and packet captures. Two independent sources agreeing is "
                   "strong evidence: triage these first.")
        for c in corr:
            st.markdown(f"""<div class="alert-card" style="--sev:{SEV_COLORS['Critical']}">
<div class="head"><span class="title">{html.escape(c['source_ip'])}</span><span class="pill">{c['alerts']} alerts</span>
<span class="pill" style="--sev:#f97316">max risk {c['max_risk']}</span></div>
<div class="chips" style="margin-top:10px"><span class="chip">Logs <b>{html.escape(', '.join(c['log_rules']))}</b></span>
<span class="chip">Network <b>{html.escape(', '.join(c['network_rules']))}</b></span>
<span class="chip">Open <b>{c['open_alerts']}</b></span>
<span class="chip">Seen <b>{html.escape(str(c['first_seen']))} → {html.escape(str(c['last_seen']))}</b></span></div>
</div>""", unsafe_allow_html=True)
    else:
        st.info("No IP has been seen in both a log file and a packet capture yet. Load the sample auth.log and the "
                "sample PCAP: the same attacker, 203.0.113.50, appears in both.")
    left, right = st.columns([3, 2])
    with left:
        st.markdown("##### Alert queue (all uploads)")
        status_filter = st.multiselect("Show statuses", db.STATUSES, default=["New", "In Progress", "Escalated"])
        rows = [r for r in db.list_alerts() if r["status"] in status_filter]
        if rows:
            st.dataframe(pd.DataFrame(rows)[["id", "status", "severity", "risk_score", "rule", "source_ip", "host",
                                             "assignee", "disposition", "created_at"]],
                         width="stretch", hide_index=True, height=420)
        else:
            st.info("No alerts with these statuses.")
    with right:
        st.markdown("##### False positives by rule")
        if m["fp_rate_by_rule"]:
            fp = pd.DataFrame(m["fp_rate_by_rule"]).sort_values("fp_rate_pct")
            fig = go.Figure(go.Bar(x=fp["fp_rate_pct"], y=fp["rule"], orientation="h", marker_color="#eab308",
                                   text=[f"{r.false_positives}/{r.closed}" for r in fp.itertuples()], textposition="auto"))
            fig.update_layout(title="Rules with high FP rates need tuning")
            fig.update_xaxes(title="% of closed alerts", range=[0, 100])
            st.plotly_chart(styled(fig, 360), width="stretch")
        else:
            st.info("Close some alerts with a disposition to see which rules need tuning.")

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
