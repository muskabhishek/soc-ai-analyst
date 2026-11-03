import { clsx, type ClassValue } from "clsx";
import type { Severity, Status } from "./api";

export const cn = (...v: ClassValue[]) => clsx(v);

export const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low"];

export const sevVar: Record<Severity, string> = {
  Critical: "var(--crit)",
  High: "var(--high)",
  Medium: "var(--med)",
  Low: "var(--low)",
};

export const statusTone: Record<Status, string> = {
  New: "bg-accent-soft text-accent",
  "In Progress": "bg-[color-mix(in_oklab,var(--med)_18%,transparent)] text-med",
  Escalated: "bg-[color-mix(in_oklab,var(--high)_18%,transparent)] text-high",
  Closed: "bg-subtle text-muted",
};

export const ruleTitle = (rule: string) =>
  rule.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

export const fmtTime = (iso?: string | null) => {
  if (!iso) return "-";
  const d = new Date(iso.includes("T") || iso.includes("Z") ? iso : iso.replace(" ", "T"));
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleString(undefined, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
};

export const fmtNum = (n?: number | null) => (n == null ? "-" : n.toLocaleString());

const ANALYST_KEY = "soc-analyst-name";
export function getAnalyst() {
  try {
    return localStorage.getItem(ANALYST_KEY) || "analyst1";
  } catch {
    return "analyst1";
  }
}
export function setAnalyst(name: string) {
  try {
    localStorage.setItem(ANALYST_KEY, name);
  } catch {
    /* storage unavailable: the name lives for this page only */
  }
}
