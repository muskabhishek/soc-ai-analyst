"use client";

import { ChevronRight } from "lucide-react";
import Link from "next/link";
import type { AlertRow } from "@/lib/api";
import { fmtTime, ruleTitle } from "@/lib/utils";
import { RiskBar, SeverityBadge, StatusBadge } from "./ui";

export function AlertsList({ alerts, empty = "No alerts: nothing suspicious was detected." }: { alerts: AlertRow[]; empty?: string }) {
  if (!alerts.length) return <p className="py-8 text-center text-sm text-muted">{empty}</p>;
  return (
    <>
      {/* phones: stacked cards */}
      <ul className="space-y-2 md:hidden">
        {alerts.map((a) => (
          <li key={a.id}>
            <Link href={`/alerts/${a.id}`} className="block rounded-xl border border-line bg-surface p-3 active:bg-subtle">
              <div className="flex items-center justify-between gap-2">
                <SeverityBadge severity={a.severity} />
                <StatusBadge status={a.status} />
              </div>
              <p className="mt-2 font-semibold">{ruleTitle(a.rule)}</p>
              <p className="mt-0.5 text-xs text-muted">
                {a.source_ip} · {a.mitre_id} · {fmtTime(a.start)}
              </p>
            </Link>
          </li>
        ))}
      </ul>

      {/* tablets and up: table */}
      <div className="-mx-4 hidden overflow-x-auto sm:-mx-5 md:block">
        <table className="w-full min-w-[760px] text-sm">
          <thead>
            <tr className="border-b border-line text-left text-xs uppercase tracking-wider text-muted">
              <th className="px-4 py-2 font-medium sm:px-5">Severity</th>
              <th className="px-2 py-2 font-medium">Alert</th>
              <th className="px-2 py-2 font-medium">Source</th>
              <th className="px-2 py-2 font-medium">MITRE</th>
              <th className="px-2 py-2 font-medium">Risk</th>
              <th className="px-2 py-2 font-medium">Status</th>
              <th className="px-2 py-2 font-medium">First seen</th>
              <th className="w-8" />
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id} className="group border-b border-line/70 last:border-0 hover:bg-subtle">
                <td className="px-4 py-2.5 sm:px-5"><SeverityBadge severity={a.severity} /></td>
                <td className="px-2 py-2.5">
                  <Link href={`/alerts/${a.id}`} className="font-medium hover:text-accent">{ruleTitle(a.rule)}</Link>
                  {a.disposition && <p className="text-xs text-muted">{a.disposition}</p>}
                </td>
                <td className="px-2 py-2.5 font-mono text-xs">{a.source_ip}</td>
                <td className="px-2 py-2.5 font-mono text-xs text-muted">{a.mitre_id}</td>
                <td className="px-2 py-2.5"><RiskBar score={a.risk_score} severity={a.severity} /></td>
                <td className="px-2 py-2.5"><StatusBadge status={a.status} /></td>
                <td className="px-2 py-2.5 text-xs text-muted whitespace-nowrap">{fmtTime(a.start)}</td>
                <td className="pr-3">
                  <Link href={`/alerts/${a.id}`} aria-label={`Open alert ${a.id}`}>
                    <ChevronRight className="size-4 text-muted group-hover:text-accent" />
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
