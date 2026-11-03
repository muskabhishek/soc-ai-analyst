"use client";

import { FileDown, Link2, Upload as UploadIcon } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import { AlertsList } from "@/components/alerts-list";
import { HBars, SeverityDonut, TimelineChart } from "@/components/charts";
import { UploadPanel } from "@/components/upload-panel";
import { Button, Card, CardTitle, ErrorBox, Kpi, PageHeader, Spinner } from "@/components/ui";
import { api, type Correlation, type UploadDetail, type UploadSummary } from "@/lib/api";
import { fmtNum, fmtTime } from "@/lib/utils";

function OverviewPage() {
  const router = useRouter();
  const params = useSearchParams();
  const [uploads, setUploads] = useState<UploadSummary[] | null>(null);
  const [detail, setDetail] = useState<UploadDetail | null>(null);
  const [corr, setCorr] = useState<Correlation[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [showUpload, setShowUpload] = useState(false);

  const selected = Number(params.get("upload")) || uploads?.[0]?.id;

  useEffect(() => {
    api.uploads().then(setUploads).catch(setError);
    api.correlations().then(setCorr).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selected) return;
    api.upload(selected).then((d) => { setDetail(d); setError(null); }).catch(setError);
  }, [selected]);

  const onUploaded = useCallback((id: number) => {
    setShowUpload(false);
    api.uploads().then(setUploads);
    api.correlations().then(setCorr).catch(() => {});
    router.push(`/?upload=${id}`);
  }, [router]);

  if (error && !uploads) return <ErrorBox error={error} />;
  if (!uploads) return <Spinner />;

  if (!uploads.length) {
    return (
      <div className="mx-auto max-w-2xl py-6">
        <PageHeader title="Welcome" subtitle="Upload security logs or a Wireshark capture. Python detects the attacks, MITRE ATT&CK names them, and a playbook guides your verdict." />
        <Card><UploadPanel onDone={onUploaded} /></Card>
      </div>
    );
  }

  const ov = detail?.overview;
  const k = ov?.kpis;
  const isPcap = detail?.kind === "pcap";
  const correlated = corr.filter((c) => detail?.alerts.some((a) => a.source_ip === c.source_ip));

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle={detail ? <>{detail.filename} · analysed {fmtTime(detail.created_at)}</> : "Loading…"}
        actions={
          <>
            <select
              aria-label="Choose an upload"
              value={selected}
              onChange={(e) => router.push(`/?upload=${e.target.value}`)}
              className="w-full rounded-xl border border-line bg-surface px-3 py-2 text-sm sm:w-auto sm:max-w-[16rem]"
            >
              {uploads.map((u) => (
                <option key={u.id} value={u.id}>#{u.id} · {u.filename} ({u.alerts} alerts)</option>
              ))}
            </select>
            <Button variant="primary" onClick={() => setShowUpload((v) => !v)}><UploadIcon className="size-4" /> Upload</Button>
            {detail && detail.alerts.length > 0 && (
              <Link href={`/report/${detail.id}`}><Button><FileDown className="size-4" /> Report</Button></Link>
            )}
          </>
        }
      />

      {showUpload && <Card className="mb-5"><UploadPanel compact onDone={onUploaded} /></Card>}
      {error != null && <div className="mb-4"><ErrorBox error={error} /></div>}
      {!detail ? <Spinner /> : (
        <div className="space-y-5">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-5">
            <Kpi label={isPcap ? "Packets" : "Events"} value={fmtNum(detail.n_events)} sub={k ? `${k.span_hours} h of activity` : undefined} />
            <Kpi label="Alerts" value={detail.alerts.length} sub="rule matches" tone="var(--c2)" />
            <Kpi label="Critical / High" value={detail.alerts.filter((a) => a.severity === "Critical" || a.severity === "High").length}
                 sub="work these first" tone="var(--crit)" />
            <Kpi label="Suspicious IPs" value={new Set(detail.alerts.map((a) => a.source_ip)).size} sub="unique sources" tone="var(--high)" />
            {isPcap
              ? <div className="col-span-2 md:col-span-1"><Kpi label="Hosts seen" value={fmtNum(k?.hosts_seen)} sub="in the capture" tone="var(--c3)" /></div>
              : <div className="col-span-2 md:col-span-1"><Kpi label="Failed logins" value={fmtNum(k?.failed_logins)} sub="authentication failures" tone="var(--c3)" /></div>}
          </div>

          {correlated.length > 0 && (
            <Card className="border-crit/40">
              <CardTitle hint="Seen attacking in both log files and packet captures: two independent sources agree.">
                <span className="inline-flex items-center gap-2"><Link2 className="size-4 text-crit" /> Cross-source attackers</span>
              </CardTitle>
              <div className="flex flex-wrap gap-2">
                {correlated.map((c) => (
                  <Link key={c.source_ip} href="/cases" className="rounded-xl border border-line bg-subtle px-3 py-2 text-sm hover:border-crit">
                    <span className="font-mono font-semibold">{c.source_ip}</span>
                    <span className="ml-2 text-xs text-muted">{c.log_rules.length + c.network_rules.length} rules · max risk {c.max_risk}</span>
                  </Link>
                ))}
              </div>
            </Card>
          )}

          {ov && (
            <div className="grid gap-5 lg:grid-cols-3">
              <Card className="lg:col-span-2">
                <CardTitle hint={`${isPcap ? "Packets by protocol" : "Events by outcome"}, ${ov.timeline.bucket} buckets`}>Activity over time</CardTitle>
                <TimelineChart timeline={ov.timeline} />
              </Card>
              <Card>
                <CardTitle hint="Pick by severity, not by time">Alerts by severity</CardTitle>
                <SeverityDonut counts={ov.severity} />
              </Card>
              <Card>
                <CardTitle hint={isPcap ? "Packets sent · red = in an alert" : "Failed logins · red = in an alert"}>Top sources</CardTitle>
                <HBars data={ov.top_sources.map((s) => ({ label: s.ip, value: s.count }))}
                       highlight={(ip) => ov.top_sources.find((s) => s.ip === ip)?.alerted ?? false} fill="var(--muted)" />
              </Card>
              <Card className={isPcap ? "" : "lg:col-span-2"}>
                <CardTitle hint="Techniques behind this upload's alerts">MITRE ATT&CK</CardTitle>
                {ov.mitre.length
                  ? <HBars data={ov.mitre.map((m) => ({ label: m.technique.split(" ")[0], value: m.count }))} fill="var(--c2)" />
                  : <p className="text-sm text-muted">No techniques: no alerts.</p>}
                <ul className="mt-2 space-y-0.5 text-xs text-muted">
                  {ov.mitre.slice(0, 6).map((m) => <li key={m.technique}>{m.technique}</li>)}
                </ul>
              </Card>
              {isPcap && ov.top_ports && (
                <Card>
                  <CardTitle hint="New TCP connections per destination port">Most-contacted ports</CardTitle>
                  <HBars data={ov.top_ports.map((p) => ({ label: String(p.port), value: p.count }))} fill="var(--c3)" />
                </Card>
              )}
            </div>
          )}

          <Card>
            <CardTitle hint="Open an alert to triage it with its playbook and 5W worksheet">Alerts</CardTitle>
            <AlertsList alerts={detail.alerts} />
          </Card>

          {isPcap && ov?.dns && ov.dns.length > 0 && (
            <div className="grid gap-5 lg:grid-cols-2">
              <Card>
                <CardTitle hint="Most frequent questions per host">DNS queries</CardTitle>
                <ul className="max-h-72 divide-y divide-line overflow-y-auto text-sm">
                  {ov.dns.map((d, i) => (
                    <li key={i} className="flex items-center justify-between gap-3 py-1.5">
                      <span className="min-w-0 truncate font-mono text-xs" title={d.query}>{d.query}</span>
                      <span className="shrink-0 text-xs text-muted">{d.source} · {d.count}</span>
                    </li>
                  ))}
                </ul>
              </Card>
              <Card>
                <CardTitle hint="Cleartext web requests seen in the capture">HTTP requests</CardTitle>
                <ul className="max-h-72 divide-y divide-line overflow-y-auto text-sm">
                  {(ov.http ?? []).map((h, i) => (
                    <li key={i} className="py-1.5">
                      <p className="truncate font-mono text-xs" title={h.host + h.uri}>
                        <span className="font-semibold text-accent">{h.method}</span> {h.host}{h.uri}
                      </p>
                      <p className="text-xs text-muted">{h.source} · {fmtTime(h.time)}</p>
                    </li>
                  ))}
                </ul>
              </Card>
            </div>
          )}
        </div>
      )}
    </>
  );
}

export default function Page() {
  return (
    <Suspense fallback={<Spinner />}>
      <OverviewPage />
    </Suspense>
  );
}
