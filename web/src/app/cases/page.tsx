"use client";

import { Link2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { AlertsList } from "@/components/alerts-list";
import { HBars } from "@/components/charts";
import { Card, CardTitle, ErrorBox, Kpi, PageHeader, Spinner } from "@/components/ui";
import { api, STATUSES, type AlertRow, type Correlation, type Metrics, type Status } from "@/lib/api";
import { cn, fmtTime, ruleTitle } from "@/lib/utils";

export default function CasesPage() {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [corr, setCorr] = useState<Correlation[]>([]);
  const [show, setShow] = useState<Status[]>(["New", "In Progress", "Escalated"]);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    Promise.all([api.metrics(), api.alerts(), api.correlations()])
      .then(([m, a, c]) => { setMetrics(m); setAlerts(a); setCorr(c); })
      .catch(setError);
  }, []);

  const queue = useMemo(() => alerts.filter((a) => show.includes(a.status)), [alerts, show]);

  if (error) return <ErrorBox error={error} />;
  if (!metrics) return <Spinner />;

  const toggle = (s: Status) => setShow((v) => (v.includes(s) ? v.filter((x) => x !== s) : [...v, s]));
  const mins = (m: number | null) => (m == null ? "-" : m < 120 ? `${m} min` : `${(m / 60).toFixed(1)} h`);

  return (
    <div className="space-y-5">
      <PageHeader title="Cases" subtitle="Every alert is a case: New → In Progress → Escalated → Closed, with a verdict and an audit trail." />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
        <Kpi label="Open cases" value={metrics.open} sub="New + In Progress + Escalated" />
        <Kpi label="Escalated" value={metrics.by_status.Escalated} sub="handed to L2 / IR" tone="var(--high)" />
        <Kpi label="MTTA" value={mins(metrics.mtta_minutes)} sub="mean time to acknowledge" tone="var(--c2)" />
        <Kpi label="MTTR" value={mins(metrics.mttr_minutes)} sub="mean time to resolve" tone="var(--c3)" />
        <Kpi label="False-positive rate" value={metrics.false_positive_rate_pct == null ? "-" : `${metrics.false_positive_rate_pct}%`}
             sub={`of ${metrics.closed} closed`} tone="var(--med)" />
      </div>

      {corr.length > 0 && (
        <Card>
          <CardTitle hint="These IPs attacked in both log files and packet captures. Triage them first.">
            <span className="inline-flex items-center gap-2"><Link2 className="size-4 text-crit" /> Cross-source correlations</span>
          </CardTitle>
          <div className="grid gap-3 md:grid-cols-2">
            {corr.map((c) => (
              <div key={c.source_ip} className="rounded-xl border border-line border-l-4 border-l-crit bg-subtle/50 p-3.5">
                <div className="flex items-center justify-between gap-2">
                  <p className="font-mono text-base font-semibold">{c.source_ip}</p>
                  <span className="text-xs text-muted">{c.alerts} alerts · max risk {c.max_risk}</span>
                </div>
                <p className="mt-2 text-xs"><span className="text-muted">Logs:</span> {c.log_rules.map(ruleTitle).join(", ")}</p>
                <p className="text-xs"><span className="text-muted">Network:</span> {c.network_rules.map(ruleTitle).join(", ")}</p>
                <p className="mt-1 text-xs text-muted">{fmtTime(c.first_seen)} → {fmtTime(c.last_seen)} · {c.open_alerts} open</p>
              </div>
            ))}
          </div>
        </Card>
      )}

      <div className="grid gap-5 xl:grid-cols-[1.6fr_1fr]">
        <Card>
          <CardTitle hint="All uploads, highest risk first">Alert queue</CardTitle>
          <div className="mb-3 flex flex-wrap gap-2">
            {STATUSES.map((s) => (
              <button key={s} onClick={() => toggle(s)} aria-pressed={show.includes(s)}
                      className={cn("rounded-full border px-3 py-1 text-xs font-medium transition",
                        show.includes(s) ? "border-accent bg-accent-soft text-accent" : "border-line text-muted hover:bg-subtle")}>
                {s} · {metrics.by_status[s] ?? 0}
              </button>
            ))}
          </div>
          <AlertsList alerts={queue} empty="No alerts with these statuses." />
        </Card>
        <Card>
          <CardTitle hint="Share of closed alerts marked False Positive. High = the rule needs tuning.">False positives by rule</CardTitle>
          {metrics.fp_rate_by_rule.length ? (
            <HBars data={metrics.fp_rate_by_rule.map((r) => ({ label: ruleTitle(r.rule), value: r.fp_rate_pct }))} fill="var(--med)" />
          ) : <p className="py-6 text-sm text-muted">Close alerts with a verdict to see which rules need tuning.</p>}
        </Card>
      </div>
    </div>
  );
}
