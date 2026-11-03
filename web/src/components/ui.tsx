"use client";

import { Check, Copy, Loader2 } from "lucide-react";
import { useState, type ButtonHTMLAttributes, type CSSProperties, type ReactNode } from "react";
import type { Severity, Status } from "@/lib/api";
import { cn, sevVar, statusTone } from "@/lib/utils";

export function Card({ className, style, children }: { className?: string; style?: CSSProperties; children: ReactNode }) {
  return <section style={style} className={cn("rounded-2xl border border-line bg-surface p-4 sm:p-5 shadow-sm", className)}>{children}</section>;
}

export function CardTitle({ children, action, hint }: { children: ReactNode; action?: ReactNode; hint?: ReactNode }) {
  return (
    <div className="mb-3 flex items-start justify-between gap-3">
      <div>
        <h2 className="text-[0.95rem] font-semibold tracking-tight">{children}</h2>
        {hint && <p className="mt-0.5 text-xs text-muted">{hint}</p>}
      </div>
      {action}
    </div>
  );
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span
      className={cn("inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold", className)}
      style={{ color: sevVar[severity], background: `color-mix(in oklab, ${sevVar[severity]} 14%, transparent)` }}
    >
      <span className="size-1.5 rounded-full" style={{ background: sevVar[severity] }} />
      {severity}
    </span>
  );
}

export function StatusBadge({ status }: { status: Status }) {
  return <span className={cn("rounded-full px-2.5 py-0.5 text-xs font-medium whitespace-nowrap", statusTone[status])}>{status}</span>;
}

export function RiskBar({ score, severity }: { score: number; severity: Severity }) {
  return (
    <div className="flex items-center gap-2" title={`Risk score ${score}/100`}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-subtle">
        <div className="h-full rounded-full" style={{ width: `${Math.min(score, 100)}%`, background: sevVar[severity] }} />
      </div>
      <span className="tabular-nums text-xs text-muted">{score}</span>
    </div>
  );
}

type Variant = "primary" | "secondary" | "ghost";
export function Button({
  variant = "secondary",
  loading,
  className,
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; loading?: boolean }) {
  return (
    <button
      {...props}
      disabled={props.disabled || loading}
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-xl px-3.5 py-2 text-sm font-medium transition",
        "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:opacity-50",
        variant === "primary" && "bg-accent text-white hover:brightness-110 dark:text-slate-950",
        variant === "secondary" && "border border-line bg-surface hover:bg-subtle",
        variant === "ghost" && "hover:bg-subtle",
        className,
      )}
    >
      {loading && <Loader2 className="size-4 animate-spin" />}
      {children}
    </button>
  );
}

export function Kpi({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string }) {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-line bg-surface p-4 shadow-sm">
      <span className="absolute inset-x-0 top-0 h-0.5" style={{ background: tone ?? "var(--accent)" }} />
      <p className="text-[0.7rem] font-medium uppercase tracking-wider text-muted">{label}</p>
      <p className="mt-1 text-2xl font-bold tabular-nums tracking-tight sm:text-[1.7rem]">{value}</p>
      {sub && <p className="mt-0.5 truncate text-xs text-muted">{sub}</p>}
    </div>
  );
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted">
      <Loader2 className="size-4 animate-spin" /> {label}…
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="rounded-xl border border-crit/30 bg-[color-mix(in_oklab,var(--crit)_8%,transparent)] p-3 text-sm text-crit">
      {msg.includes("fetch") || msg.includes("502") || msg.includes("500")
        ? "Cannot reach the API. Start it with: uvicorn api.main:app"
        : msg}
    </div>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      variant="ghost"
      className="px-2 py-1 text-xs"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          /* clipboard blocked (e.g. plain http on a phone): the text stays selectable */
        }
      }}
    >
      {done ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
      {done ? "Copied" : label}
    </Button>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        <h1 className="text-xl font-bold tracking-tight sm:text-2xl">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
