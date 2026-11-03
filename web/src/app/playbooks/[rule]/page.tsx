"use client";

import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { AlertsList } from "@/components/alerts-list";
import { Card, CardTitle, CopyButton, ErrorBox, PageHeader, Spinner } from "@/components/ui";
import { api, FIVE_WS, type AlertRow, type Playbook } from "@/lib/api";

const W_LABEL = { who: "Who", what: "What", when: "When", where: "Where", why: "Why", how: "How" } as const;

function Signs({ title, items, tone }: { title: string; items: string[]; tone: string }) {
  return (
    <div className="rounded-2xl border border-line border-t-4 bg-surface p-4 shadow-sm" style={{ borderTopColor: tone }}>
      <p className="mb-2 text-sm font-semibold">{title}</p>
      <ul className="list-disc space-y-1 pl-4 text-sm text-muted">{items.map((i) => <li key={i}>{i}</li>)}</ul>
    </div>
  );
}

export default function PlaybookPage() {
  const rule = useParams<{ rule: string }>().rule;
  const [pb, setPb] = useState<Playbook | null>(null);
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    Promise.all([api.playbook(rule), api.alerts()])
      .then(([p, a]) => { setPb(p); setAlerts(a.filter((x) => x.rule === rule && x.status !== "Closed")); })
      .catch(setError);
  }, [rule]);

  if (error) return <ErrorBox error={error} />;
  if (!pb) return <Spinner />;

  return (
    <div className="space-y-5">
      <Link href="/playbooks" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink">
        <ArrowLeft className="size-4" /> All playbooks
      </Link>
      <PageHeader title={pb.title} subtitle={`${pb.group === "Logs" ? "Log" : "Network"} alert playbook`} />

      <div className="grid gap-5 xl:grid-cols-[1.5fr_1fr]">
        <div className="space-y-5">
          <Card>
            <p className="text-sm"><span className="font-semibold">What it means. </span>{pb.summary}</p>
            <p className="mt-2 text-sm"><span className="font-semibold">Why attackers do it. </span>{pb.why_attackers}</p>
          </Card>

          <Card>
            <CardTitle hint="Answer these from the evidence; the alert page pre-fills most of them">The 5 Ws for this alert</CardTitle>
            <dl className="divide-y divide-line">
              {FIVE_WS.map((w) => (
                <div key={w} className="grid grid-cols-[4.5rem_1fr] gap-3 py-2 text-sm">
                  <dt className="font-semibold">{W_LABEL[w]}</dt>
                  <dd className="text-muted">{pb.five_ws[w].ask}</dd>
                </div>
              ))}
            </dl>
          </Card>

          <div className="grid gap-4 md:grid-cols-2">
            <Signs title="Signs of a True Positive" items={pb.true_positive_signs} tone="var(--crit)" />
            <Signs title="Signs of a False Positive" items={pb.false_positive_signs} tone="var(--low)" />
          </div>

          <Card>
            <CardTitle>How to investigate</CardTitle>
            <ol className="list-decimal space-y-1.5 pl-5 text-sm">{pb.investigate.map((s) => <li key={s}>{s}</li>)}</ol>
          </Card>

          <Card>
            <CardTitle>Deciding the verdict</CardTitle>
            <ul className="space-y-2 text-sm">
              <li><span className="font-semibold text-crit">True Positive: </span>{pb.verdict_guide.true_positive}</li>
              <li><span className="font-semibold text-low">False Positive: </span>{pb.verdict_guide.false_positive}</li>
              <li><span className="font-semibold text-high">Escalate when: </span>{pb.verdict_guide.escalate}</li>
            </ul>
            <p className="mb-1 mt-4 text-sm font-semibold">Next steps after a True Positive</p>
            <ul className="list-disc space-y-1 pl-5 text-sm text-muted">{pb.next_steps.map((s) => <li key={s}>{s}</li>)}</ul>
          </Card>
        </div>

        <div className="space-y-5">
          <Card>
            <CardTitle hint="Open one to triage it with this playbook">Open alerts of this type</CardTitle>
            <AlertsList alerts={alerts} empty="No open alerts of this type. Load a sample on the Overview page to practise." />
          </Card>
          <Card>
            <CardTitle action={<CopyButton text={pb.comment_template} />}>Closing-comment template</CardTitle>
            <pre className="whitespace-pre-wrap rounded-xl bg-subtle p-3 font-mono text-xs">{pb.comment_template}</pre>
          </Card>
        </div>
      </div>
    </div>
  );
}
