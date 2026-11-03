"use client";

import {
  Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import type { Overview, Severity } from "@/lib/api";
import { SEVERITIES, sevVar } from "@/lib/utils";

const SERIES_COLOR: Record<string, string> = {
  failure: "var(--crit)", success: "var(--c1)", info: "var(--c2)",
  TCP: "var(--c1)", DNS: "var(--c2)", HTTP: "var(--c3)", FTP: "var(--c4)", UDP: "var(--c6)", ICMP: "var(--c5)",
};
const color = (name: string, i: number) => SERIES_COLOR[name] ?? `var(--c${(i % 6) + 1})`;

const axis = { stroke: "var(--muted)", fontSize: 11, tickLine: false, axisLine: false } as const;
const tooltip = {
  contentStyle: {
    background: "var(--surface)", border: "1px solid var(--line)", borderRadius: 12, fontSize: 12, color: "var(--ink)",
  },
  labelStyle: { color: "var(--muted)", marginBottom: 4 },
  cursor: { fill: "var(--subtle)" },
};

const shortTime = (iso: string) => {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
};

export function TimelineChart({ timeline }: { timeline: Overview["timeline"] }) {
  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={timeline.points} margin={{ top: 8, right: 4, left: -6, bottom: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--grid)" />
          <XAxis dataKey="t" tickFormatter={shortTime} minTickGap={28} {...axis} />
          <YAxis allowDecimals={false} width={44} {...axis} />
          <Tooltip {...tooltip} labelFormatter={(v) => new Date(String(v)).toLocaleString()} />
          <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12, color: "var(--muted)" }} />
          {timeline.series.map((s, i) => (
            <Bar key={s} dataKey={s} stackId="a" fill={color(s, i)} radius={i === timeline.series.length - 1 ? [3, 3, 0, 0] : 0} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function SeverityDonut({ counts }: { counts: Record<Severity, number> }) {
  const data = SEVERITIES.map((s) => ({ name: s, value: counts[s] ?? 0 })).filter((d) => d.value > 0);
  const total = data.reduce((n, d) => n + d.value, 0);
  return (
    <div className="flex items-center gap-4">
      <div className="relative h-44 w-44 shrink-0">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" innerRadius="66%" outerRadius="100%" paddingAngle={2} stroke="var(--surface)" strokeWidth={2}>
              {data.map((d) => <Cell key={d.name} fill={sevVar[d.name as Severity]} />)}
            </Pie>
            <Tooltip {...tooltip} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
          <div>
            <p className="text-2xl font-bold tabular-nums">{total}</p>
            <p className="text-xs text-muted">alerts</p>
          </div>
        </div>
      </div>
      <ul className="space-y-2 text-sm">
        {SEVERITIES.map((s) => (
          <li key={s} className="flex items-center gap-2">
            <span className="size-2.5 rounded-full" style={{ background: sevVar[s] }} />
            <span className="w-16 text-muted">{s}</span>
            <span className="font-semibold tabular-nums">{counts[s] ?? 0}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function HBars({ data, highlight, fill = "var(--c1)", height }: {
  data: { label: string; value: number }[];
  highlight?: (label: string) => boolean;
  fill?: string;
  height?: number;
}) {
  return (
    <div style={{ height: height ?? Math.max(120, data.length * 34) }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 12, left: 0, bottom: 0 }}>
          <XAxis type="number" allowDecimals={false} hide />
          <YAxis type="category" dataKey="label" width={112} {...axis} tick={{ fill: "var(--ink)", fontSize: 11 }} />
          <Tooltip {...tooltip} />
          <Bar dataKey="value" radius={[0, 6, 6, 0]} barSize={16}>
            {data.map((d) => <Cell key={d.label} fill={highlight?.(d.label) ? "var(--crit)" : fill} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
