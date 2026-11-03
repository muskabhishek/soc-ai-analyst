"use client";

import { Save } from "lucide-react";
import { useState } from "react";
import { api, FIVE_WS, STATUSES, VERDICTS, type AlertDetail, type Status, type TriageContext, type W, type Worksheet } from "@/lib/api";
import { cn, getAnalyst } from "@/lib/utils";
import { Button, CopyButton, ErrorBox } from "./ui";

const LEAN = {
  TP: { dot: "bg-crit", text: "points to an attack" },
  FP: { dot: "bg-low", text: "points to benign activity" },
  info: { dot: "bg-muted/60", text: "context" },
} as const;

const W_LABEL: Record<W, string> = { who: "Who", what: "What", when: "When", where: "Where", why: "Why", how: "How" };

export function TriageForm({ alert, ctx, worksheet, onSaved }: {
  alert: AlertDetail;
  ctx: TriageContext;
  worksheet: Worksheet;
  onSaved: () => void;
}) {
  const [answers, setAnswers] = useState<Record<W, string>>(() =>
    Object.fromEntries(FIVE_WS.map((w) => [w, worksheet.answers?.[w] ?? ctx.five_ws[w].auto])) as Record<W, string>);
  const [verdict, setVerdict] = useState(worksheet.verdict || alert.disposition || "");
  const [status, setStatus] = useState<Status>(alert.status === "New" ? "In Progress" : alert.status);
  const [assignee, setAssignee] = useState(alert.assignee || "");
  const [comment, setComment] = useState(worksheet.comment ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const [label, why] = ctx.suggested_verdict;
  const tone = label.startsWith("Likely True") ? "var(--crit)" : label.startsWith("Possibly False") ? "var(--low)" : "var(--med)";
  const closingWithoutVerdict = status === "Closed" && !verdict;

  async function save() {
    setSaving(true);
    setError(null);
    try {
      const author = getAnalyst();
      await api.saveTriage(alert.db_id, { answers, verdict, comment, status, assignee: assignee || author, author });
      onSaved();
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-line border-l-4 bg-subtle/60 p-3.5" style={{ borderLeftColor: tone }}>
        <p className="text-sm font-semibold">Suggested: {label}</p>
        <p className="mt-0.5 text-xs text-muted">{why} A suggestion from the evidence; you make the call.</p>
        <ul className="mt-2.5 space-y-1.5">
          {ctx.signals.map(([text, lean], i) => (
            <li key={i} className="flex gap-2 text-sm">
              <span className={cn("mt-1.5 size-2 shrink-0 rounded-full", LEAN[lean].dot)} />
              <span>{text} <span className="text-xs text-muted">({LEAN[lean].text})</span></span>
            </li>
          ))}
        </ul>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        {FIVE_WS.map((w) => (
          <label key={w} className={cn("block", w === "why" && "sm:col-span-2")}>
            <span className="flex items-baseline justify-between gap-2 text-sm font-medium">
              {W_LABEL[w]}
              {w === "why" && <span className="text-xs font-normal text-high">Your judgement: the tool cannot know this</span>}
            </span>
            <span className="mb-1 block text-xs text-muted">{ctx.five_ws[w].ask}</span>
            <textarea
              value={answers[w]}
              onChange={(e) => setAnswers({ ...answers, [w]: e.target.value })}
              rows={w === "why" ? 3 : 2}
              placeholder={ctx.five_ws[w].ask}
              className={cn(
                "w-full resize-y rounded-xl border border-line bg-surface px-3 py-2 text-sm outline-none focus:border-accent [field-sizing:content] min-h-[3.25rem]",
                w === "why" && !answers.why && "border-high/60",
              )}
            />
          </label>
        ))}
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <label className="block text-sm font-medium">
          Verdict
          <select value={verdict} onChange={(e) => setVerdict(e.target.value)}
                  className="mt-1 w-full rounded-xl border border-line bg-surface px-3 py-2 text-sm">
            <option value="">Not decided yet</option>
            {VERDICTS.map((v) => <option key={v}>{v}</option>)}
          </select>
        </label>
        <label className="block text-sm font-medium">
          Status
          <select value={status} onChange={(e) => setStatus(e.target.value as Status)}
                  className="mt-1 w-full rounded-xl border border-line bg-surface px-3 py-2 text-sm">
            {STATUSES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </label>
        <label className="block text-sm font-medium">
          Assignee
          <input value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="you"
                 className="mt-1 w-full rounded-xl border border-line bg-surface px-3 py-2 text-sm outline-none focus:border-accent" />
        </label>
      </div>

      <label className="block text-sm font-medium">
        Closing comment
        <textarea value={comment} onChange={(e) => setComment(e.target.value)} rows={3}
                  placeholder="Leave empty and it will be written from your 5W answers and verdict."
                  className="mt-1 w-full resize-y rounded-xl border border-line bg-surface px-3 py-2 text-sm outline-none focus:border-accent" />
      </label>

      {closingWithoutVerdict && <p className="text-xs text-crit">Pick a verdict before closing.</p>}
      {error != null && <ErrorBox error={error} />}
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" onClick={save} loading={saving} disabled={closingWithoutVerdict}>
          <Save className="size-4" /> Save triage
        </Button>
        {!answers.why && verdict && <span className="text-xs text-high">Tip: the Why usually decides True vs False Positive.</span>}
      </div>

      {worksheet.comment && (
        <div className="rounded-xl border border-line bg-subtle/60 p-3.5">
          <div className="mb-1 flex items-center justify-between gap-2">
            <p className="text-xs text-muted">Saved by {worksheet.author} · ready to paste into a ticket</p>
            <CopyButton text={worksheet.comment} />
          </div>
          <p className="text-sm">{worksheet.comment}</p>
        </div>
      )}
    </div>
  );
}
