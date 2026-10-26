"""Shared look and components for the dashboard pages: styling, KPI cards, the playbook view and the 5W worksheet."""
import html

import streamlit as st

from src import db
from src import playbooks as P

SEV_COLORS = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#eab308", "Low": "#22c55e"}
SEV_DOTS = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
SEV_ORDER = ["Critical", "High", "Medium", "Low"]
LEAN = {"TP": ("🔴", "points to an attack"), "FP": ("🟢", "points to benign activity"), "info": ("⚪", "context")}
TIMELINE_ICONS = {"created": "🆕", "status": "🔁", "assign": "👤", "note": "📝", "worksheet": "🧭"}

CSS = """<style>
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
.signs {background: #111a2e; border: 1px solid #1f2a44; border-top: 3px solid var(--accent); border-radius: 12px; padding: 12px 16px;}
.signs .t {margin: 0 0 6px; color: #f8fafc; font-weight: 700; font-size: 1.02rem;}
.signs ul {margin: 0; padding-left: 18px; color: #cbd5e1; font-size: .9rem;}
.verdict {border-radius: 12px; padding: 12px 16px; border: 1px solid #1f2a44; background: #111a2e; border-left: 5px solid var(--accent);}
.verdict b {color: #f8fafc;} .verdict span {color: #94a3b8; font-size: .88rem;}
</style>"""


def apply_style():
    st.markdown(CSS, unsafe_allow_html=True)


def hero(title="🛡️ AI-Powered SOC Analyst",
         subtitle="Tier-1 triage for security logs and Wireshark packet captures: detect, classify, prioritise and report.",
         tags=("Python detects", "MITRE ATT&amp;CK classifies", "Local LLM explains", "Defensive use on your own logs only")):
    chips = "".join(f"<span>{t}</span>" for t in tags)
    st.markdown(f'<div class="hero"><h1>{title}</h1><p>{subtitle}</p><div class="tags">{chips}</div></div>',
                unsafe_allow_html=True)


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


def _signs_box(title, items, accent):
    li = "".join(f"<li>{html.escape(i)}</li>" for i in items)
    return f'<div class="signs" style="--accent:{accent}"><div class="t">{title}</div><ul>{li}</ul></div>'


def render_playbook(pb):
    """The static playbook: meaning, 5W questions, TP vs FP signs, investigation, verdict guide, next steps."""
    st.markdown(f"### {pb['title']}")
    st.markdown(f"**What it means.** {pb['summary']}")
    st.markdown(f"**Why attackers do it.** {pb['why_attackers']}")
    st.markdown("##### The 5 Ws for this alert")
    st.table({"": [P.W_LABELS[w] for w in P.FIVE_WS], "Ask yourself": [pb["five_ws"][w]["ask"] for w in P.FIVE_WS]})
    left, right = st.columns(2)
    left.markdown(_signs_box("🔴 Signs of a True Positive", pb["true_positive_signs"], SEV_COLORS["Critical"]),
                  unsafe_allow_html=True)
    right.markdown(_signs_box("🟢 Signs of a False Positive", pb["false_positive_signs"], SEV_COLORS["Low"]),
                   unsafe_allow_html=True)
    st.markdown("##### How to investigate")
    st.markdown("\n".join(f"{i}. {step}" for i, step in enumerate(pb["investigate"], 1)))
    g = pb["verdict_guide"]
    st.markdown("##### Deciding the verdict")
    st.markdown(f"- **True Positive:** {g['true_positive']}\n- **False Positive:** {g['false_positive']}\n"
                f"- **Escalate when:** {g['escalate']}")
    st.markdown("##### Next steps after a True Positive")
    st.markdown("\n".join(f"- {s}" for s in pb["next_steps"]))


def render_signals(pb, alert, related):
    signals = P.evidence_signals(pb, alert, related)
    label, why = P.suggest_verdict(signals)
    accent = {"Likely True Positive": SEV_COLORS["Critical"], "Possibly False Positive": SEV_COLORS["Low"]}.get(
        label, SEV_COLORS["Medium"])
    st.markdown(f'<div class="verdict" style="--accent:{accent}"><b>Suggested: {label}</b><br><span>{html.escape(why)} '
                f'This is a suggestion from the evidence; you make the call.</span></div>', unsafe_allow_html=True)
    for text, lean in signals:
        icon, meaning = LEAN[lean]
        st.markdown(f"{icon} {html.escape(text)} <span style='color:#64748b'>({meaning})</span>", unsafe_allow_html=True)


def render_worksheet(alert, cid, analyst, related=(), key="ws"):
    """5W worksheet for one stored alert: pre-filled answers, verdict, comment; saving also updates the case."""
    pb = P.get_playbook(alert["rule"])
    info = db.get_alert(cid)
    if not pb or not info:
        st.info("No playbook for this alert type yet.")
        return
    saved = db.get_worksheet(cid) or {}
    auto = P.fill_five_ws(pb, alert, related)
    st.markdown("#### 🧭 5W triage worksheet")
    render_signals(pb, alert, related)
    st.write("")
    with st.form(f"{key}-{cid}", border=True):
        c1, c2 = st.columns(2)
        owner = c1.text_input("Assignee", info.get("assignee") or analyst, key=f"{key}-owner-{cid}")
        status = c2.selectbox("Status", db.STATUSES, index=db.STATUSES.index(info["status"] if info["status"] != "New"
                                                                             else "In Progress"),
                              key=f"{key}-status-{cid}")
        answers = {}
        for w in P.FIVE_WS:
            answers[w] = st.text_area(
                P.W_LABELS[w], saved.get("answers", {}).get(w, auto[w]["auto"]), key=f"{key}-{w}-{cid}",
                height=68, placeholder=auto[w]["ask"], help=auto[w]["ask"])
        verdicts = ["-"] + db.DISPOSITIONS
        current = saved.get("verdict") or info.get("disposition") or "-"
        verdict = st.selectbox("Verdict (required to close)", verdicts, index=verdicts.index(current)
                               if current in verdicts else 0, key=f"{key}-verdict-{cid}")
        comment = st.text_area("Closing comment", saved.get("comment", ""), key=f"{key}-comment-{cid}", height=110,
                               placeholder="Leave empty and it will be written from your 5W answers and verdict.")
        submitted = st.form_submit_button("💾 Save worksheet and update case", type="primary")
    if submitted:
        v = "" if verdict == "-" else verdict
        if status == "Closed" and not v:
            st.error("Pick a verdict before closing: True Positive, Benign True Positive or False Positive.")
            return
        if not answers["why"].strip() and v:
            st.warning("Saved without a Why. The Why is usually what separates a True from a False Positive.")
        final = comment.strip() or P.draft_comment(pb, alert, answers, v, related)
        db.save_worksheet(cid, {"answers": answers, "verdict": v, "comment": final}, analyst)
        if owner and owner != (info.get("assignee") or ""):
            db.assign(cid, owner, analyst)
        if status != info["status"] or (status == "Closed" and v != (info.get("disposition") or "")):
            db.update_status(cid, status, analyst, v or None)
        st.rerun()
    if saved:
        st.caption(f"Last saved by {saved.get('author', '?')} at {saved.get('updated_at', '?')} UTC. "
                   "Closing comment, ready to paste into a ticket:")
        st.code(saved.get("comment", ""), language=None, wrap_lines=True)
    with st.expander("Activity timeline"):
        for ev in reversed(db.get_activity(cid)):
            icon = TIMELINE_ICONS.get(ev["action"], "•")
            detail = html.escape(ev["detail"]).replace("\n", "  \n")
            st.markdown(f"{icon} `{ev['created_at']} UTC` **{html.escape(ev['author'])}**: {detail}")
