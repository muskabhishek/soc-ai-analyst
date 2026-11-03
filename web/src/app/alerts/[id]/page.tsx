"use client";

import { ArrowLeft, BookOpen, Compass, PlusCircle, RefreshCw, Sparkles, StickyNote, UserRound } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { Markdown } from "@/components/markdown";
import { TriageForm } from "@/components/triage-form";
import { Button, Card, CardTitle, CopyButton, ErrorBox, SeverityBadge, Spinner, StatusBadge } from "@/components/ui";
import { api, type Activity, type AlertDetail, type TriageContext, type Worksheet } from "@/lib/api";
import { fmtTime, ruleTitle, sevVar } from "@/lib/utils";

const ICON = { created: PlusCircle, status: RefreshCw, assign: UserRound, note: StickyNote, worksheet: Compass } as const;

function Fact({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0 rounded-xl bg-subtle/70 px-3 py-2">
      <p className="text-[0.68rem] uppercase tracking-wider text-muted">{label}</p>
      <p className={`truncate text-sm font-medium ${mono ? "font-mono" : ""}`} title={typeof value === "string" ? value : undefined}>{value}</p>
    </div>
  );
}

export default function AlertPage() {
  const id = Number(useParams<{ id: string }>().id);
  const [alert, setAlert] = useState<AlertDetail | null>(null);
  const [ctx, setCtx] = useState<TriageContext | null>(null);
  const [ws, setWs] = useState<Worksheet>({});
  const [activity, setActivity] = useState<Activity[]>([]);
  const [explanation, setExplanation] = useState<{ text: string; source: string; warnings: string[] } | null>(null);
  const [explaining, setExplaining] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [version, setVersion] = useState(0);

  const load = useCallback(async () => {
    try {
      const a = await api.alert(id);
      setAlert(a);
      if (a.report) setExplanation(a.report);
      const [c, w, act] = await Promise.all([api.triageContext(a.rule, id), api.worksheet(id), api.activity(id)]);
      setCtx(c);
      setWs(w);
      setActivity(act);
      setVersion((v) => v + 1);
    } catch (e) {
      setError(e);
    }
  }, [id]);

  // eslint-disable-next-line react-hooks/set-state-in-effect -- fetch on mount / when the alert id changes
  useEffect(() => { load(); }, [load]);

  if (error) return <ErrorBox error={error} />;
  if (!alert || !ctx) return <Spinner />;

  const peer = alert.peer_ip;
  return (
    <div className="space-y-5">
      <Link href={`/?upload=${alert.upload_id}`} className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink">
        <ArrowLeft className="size-4" /> Back to overview
      </Link>

      <Card className="border-l-4" style={{ borderLeftColor: sevVar[alert.severity] }}>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={alert.severity} />
          <StatusBadge status={alert.status} />
          {alert.disposition && <span className="rounded-full bg-subtle px-2.5 py-0.5 text-xs">{alert.disposition}</span>}
          <span className="ml-auto text-xs text-muted">Alert #{alert.db_id}</span>
        </div>
        <h1 className="mt-3 text-xl font-bold tracking-tight sm:text-2xl">{ruleTitle(alert.rule)}</h1>
        <p className="mt-1.5 text-sm text-muted">{alert.description}</p>
        <div className="mt-4 grid grid-cols-2 gap-2 md:grid-cols-4">
          <Fact label="Source" value={alert.source_ip} mono />
          <Fact label={peer ? "Destination" : "Host"} value={peer || alert.host} mono />
          <Fact label="Events" value={alert.count} />
          <Fact label="Risk score" value={`${alert.risk_score} / 100`} />
          <Fact label="First seen" value={fmtTime(alert.start)} />
          <Fact label="Last seen" value={fmtTime(alert.end)} />
          <Fact label="Users" value={alert.users?.join(", ") || "-"} />
          <Fact label="MITRE ATT&CK" value={`${alert.mitre.id} · ${alert.mitre.tactic}`} />
        </div>
        <p className="mt-2 text-xs text-muted">{alert.mitre.id} {alert.mitre.name}</p>
        <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-subtle">
          <div className="h-full rounded-full" style={{ width: `${alert.risk_score}%`, background: sevVar[alert.severity] }} />
        </div>
      </Card>

      {alert.wireshark_filter && (
        <Card>
          <CardTitle hint="Paste into Wireshark's filter bar to jump to the evidence packets"
                     action={<CopyButton text={alert.wireshark_filter} />}>Wireshark display filter</CardTitle>
          <pre className="overflow-x-auto rounded-xl bg-subtle px-3 py-2.5 font-mono text-xs">{alert.wireshark_filter}</pre>
        </Card>
      )}

      <div className="grid gap-5 xl:grid-cols-[1.4fr_1fr]">
        <Card>
          <CardTitle
            hint="Answer Who, What, When, Where, Why and How from the evidence, then decide"
            action={<Link href={`/playbooks/${alert.rule}`}><Button className="py-1.5 text-xs"><BookOpen className="size-3.5" /> Playbook</Button></Link>}
          >
            5W triage
          </CardTitle>
          <TriageForm key={version} alert={alert} ctx={ctx} worksheet={ws} onSaved={load} />
        </Card>

        <div className="space-y-5">
          <Card>
            <CardTitle
              hint={explanation ? `Written by ${explanation.source}` : "Five-section analyst report for this alert"}
              action={
                <Button className="py-1.5 text-xs" loading={explaining}
                        onClick={async () => {
                          setExplaining(true);
                          try { setExplanation(await api.explain(id)); } catch (e) { setError(e); } finally { setExplaining(false); }
                        }}>
                  <Sparkles className="size-3.5" /> {explanation ? "Regenerate" : "Explain"}
                </Button>
              }
            >
              Analyst explanation
            </CardTitle>
            {explanation ? (
              <>
                <Markdown>{explanation.text}</Markdown>
                {explanation.warnings.map((w) => <p key={w} className="mt-2 text-xs text-high">⚠ {w}</p>)}
              </>
            ) : <p className="text-sm text-muted">Generate a summary, evidence, likely attack, severity reasoning and next steps.</p>}
          </Card>

          <Card>
            <CardTitle hint="Every change to this case, newest first">Activity</CardTitle>
            <ol className="space-y-3">
              {[...activity].reverse().map((a, i) => (
                <li key={i} className="flex gap-3 text-sm">
                  {(() => { const I = ICON[a.action as keyof typeof ICON] ?? StickyNote; return <span className="mt-0.5 grid size-6 shrink-0 place-items-center rounded-full bg-subtle text-muted"><I className="size-3.5" /></span>; })()}
                  <div className="min-w-0">
                    <p className="text-xs text-muted">{fmtTime(a.created_at + "Z")} · {a.author}</p>
                    <p className="whitespace-pre-line break-words">{a.detail}</p>
                  </div>
                </li>
              ))}
            </ol>
          </Card>
        </div>
      </div>

      <Card>
        <CardTitle hint={`${alert.evidence.length} raw ${alert.data_source === "pcap" ? "packets" : "events"} behind this alert`}>Evidence</CardTitle>
        <div className="-mx-4 max-h-96 overflow-auto sm:-mx-5">
          <table className="w-full min-w-[640px] text-xs">
            <thead className="sticky top-0 bg-surface">
              <tr className="border-b border-line text-left text-muted">
                {Object.keys(alert.evidence[0] ?? {}).map((k) => <th key={k} className="px-3 py-2 font-medium first:pl-4 sm:first:pl-5">{k}</th>)}
              </tr>
            </thead>
            <tbody className="font-mono">
              {alert.evidence.map((row, i) => (
                <tr key={i} className="border-b border-line/60">
                  {Object.values(row).map((v, j) => <td key={j} className="px-3 py-1.5 whitespace-nowrap first:pl-4 sm:first:pl-5">{String(v ?? "")}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
