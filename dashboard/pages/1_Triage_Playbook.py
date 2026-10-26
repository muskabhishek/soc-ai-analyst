"""Triage Playbook page: the triage method, one playbook per detection rule, and a 5W worksheet for any stored alert."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))   # project root, for src
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))   # dashboard/, for ui

import pandas as pd
import streamlit as st

from src import db
from src import playbooks as P
from ui import SEV_DOTS, apply_style, hero, render_playbook, render_worksheet

st.set_page_config(page_title="Triage Playbook", page_icon="📖", layout="wide")
db.init_db()
apply_style()

with st.sidebar:
    st.markdown("### 📖 Triage Playbook")
    analyst = st.text_input("Analyst name", st.session_state.get("analyst_name", "analyst1"))
    st.session_state["analyst_name"] = analyst
    st.page_link("app.py", label="Back to the dashboard", icon="🛡️")

hero("📖 Triage Playbook",
     "How an L1 analyst decides True or False Positive: the method, a playbook for every alert type, "
     "and a 5W worksheet that saves your reasoning into the case.",
     ("Who · What · When · Where · Why · How", "Evidence first", "You make the call"))

books = P.load_playbooks()
order = sorted(books, key=lambda r: (books[r]["group"] != "Logs", books[r]["title"]))
wanted = st.session_state.pop("pb_rule", None) or st.query_params.get("rule")
focus_alert = st.session_state.pop("pb_alert", None)
if wanted in books:
    st.session_state["pb_choice"] = wanted

TABS = ["🧭 The triage method", "📚 Playbooks and worksheet"]
# arriving from an alert in the dashboard: open straight on that alert's playbook
tab_method, tab_books = st.tabs(TABS, default=TABS[1] if wanted in books else None)

with tab_method:
    st.markdown(P.method_guide())
    st.info("Open the **Playbooks and worksheet** tab to see how this method applies to each alert type, "
            "or use **Open playbook** on any alert in the dashboard.")

with tab_books:
    if wanted in books:
        st.caption("Opened from the dashboard: this is the playbook for the alert you were investigating.")
    rule = st.selectbox("Playbook", order, key="pb_choice",
                        format_func=lambda r: f"{'📄' if books[r]['group'] == 'Logs' else '🦈'}  {books[r]['title']}")
    pb = books[rule]
    left, right = st.columns([3, 2], gap="large")
    with left:
        render_playbook(pb)
    with right:
        st.markdown("### Alerts using this playbook")
        show_closed = st.toggle("Include closed alerts", value=False)
        rows = [r for r in db.list_alerts() if r["rule"] == rule and (show_closed or r["status"] != "Closed")]
        if not rows:
            st.info("No alerts of this type yet. Load a sample in the dashboard to practise on one.")
            chosen = None
        else:
            st.dataframe(pd.DataFrame([{"Alert": r["id"], "Severity": f"{SEV_DOTS.get(r['severity'], '')} {r['severity']}",
                                        "Source": r["source_ip"], "Status": r["status"], "Verdict": r["disposition"] or "-"}
                                       for r in rows]), hide_index=True, width="stretch")
            ids = [r["id"] for r in rows]
            if focus_alert in ids:
                st.session_state["pb_alert_choice"] = focus_alert
            chosen = st.selectbox("Work on alert", ids, key="pb_alert_choice",
                                  format_func=lambda i: next(f"#{i} · {r['severity']} · {r['source_ip']} · {r['status']}"
                                                             for r in rows if r["id"] == i))
        st.markdown("##### Closing-comment template")
        st.code(pb["comment_template"], language=None, wrap_lines=True)

    if chosen:
        st.divider()
        row = next(r for r in rows if r["id"] == chosen)
        alert = db.get_alert(chosen)
        related = db.list_alerts(upload_id=row["upload_id"])        # same upload: other rules hit by the same IP
        st.markdown(f"### Alert #{chosen}: {alert['description']}")
        local = {v: k for k, v in st.session_state.get("db_ids", {}).items()}
        if chosen in local and st.button("🛡️ Show this alert in the dashboard"):
            st.session_state["focus_alert"] = local[chosen]
            st.switch_page("app.py")
        render_worksheet(alert, chosen, analyst, related, key="pb")
