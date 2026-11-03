// Typed client for the FastAPI backend. Every call goes to /api/..., which next.config.ts forwards to FastAPI.

export type Severity = "Critical" | "High" | "Medium" | "Low";
export type Status = "New" | "In Progress" | "Escalated" | "Closed";
export const STATUSES: Status[] = ["New", "In Progress", "Escalated", "Closed"];
export const VERDICTS = ["True Positive", "Benign True Positive", "False Positive"] as const;

export interface UploadSummary {
  id: number;
  filename: string;
  n_events: number;
  kind: "logs" | "pcap" | null;
  created_at: string;
  alerts: number;
  urgent: number | null;
  open: number | null;
}

export interface AlertRow {
  id: number;
  upload_id: number;
  rule: string;
  severity: Severity;
  risk_score: number;
  source_ip: string;
  host: string;
  count: number;
  start: string;
  end: string;
  mitre_id: string;
  status: Status;
  disposition: string | null;
  assignee: string | null;
  created_at: string | null;
}

export interface Overview {
  kind: "logs" | "pcap";
  kpis: {
    events: number;
    alerts: number;
    critical_high: number;
    suspicious_ips: number;
    failed_logins: number;
    hosts_seen: number;
    span_hours: number;
    first: string;
    last: string;
  };
  timeline: { bucket: string; series: string[]; points: Record<string, number | string>[] };
  top_sources: { ip: string; count: number; alerted: boolean }[];
  severity: Record<Severity, number>;
  mitre: { technique: string; count: number }[];
  top_ports?: { port: number; count: number }[];
  dns?: { source: string; query: string; count: number }[];
  http?: { time: string; source: string; method: string; host: string; uri: string }[];
}

export interface UploadDetail extends Omit<UploadSummary, "alerts" | "urgent" | "open"> {
  overview: Overview | null;
  alerts: AlertRow[];
}

export interface AlertDetail {
  db_id: number;
  upload_id: number;
  rule: string;
  severity: Severity;
  risk_score: number;
  source_ip: string;
  peer_ip?: string | null;
  host: string;
  users: string[];
  count: number;
  start: string;
  end: string;
  description: string;
  evidence: Record<string, string | number | null>[];
  mitre: { id: string; name: string; tactic: string };
  wireshark_filter?: string;
  data_source?: string;
  status: Status;
  disposition: string | null;
  assignee: string | null;
  created_at: string | null;
  report: { text: string; source: string; warnings: string[] } | null;
}

export type W = "who" | "what" | "when" | "where" | "why" | "how";
export const FIVE_WS: W[] = ["who", "what", "when", "where", "why", "how"];

export interface Playbook {
  rule: string;
  title: string;
  group: "Logs" | "Network";
  summary: string;
  why_attackers: string;
  five_ws: Record<W, { ask: string; auto: string }>;
  true_positive_signs: string[];
  false_positive_signs: string[];
  investigate: string[];
  verdict_guide: { true_positive: string; false_positive: string; escalate: string };
  comment_template: string;
  next_steps: string[];
}

export interface TriageContext {
  playbook: Playbook;
  five_ws: Record<W, { ask: string; auto: string }>;
  signals: [string, "TP" | "FP" | "info"][];
  suggested_verdict: [string, string];
  draft_comment: string;
}

export interface Worksheet {
  answers?: Partial<Record<W, string>>;
  verdict?: string;
  comment?: string;
  author?: string;
  updated_at?: string;
}

export interface Activity {
  author: string;
  action: string;
  detail: string;
  created_at: string;
}

export interface Metrics {
  by_status: Record<Status, number>;
  open: number;
  mtta_minutes: number | null;
  mttr_minutes: number | null;
  closed: number;
  false_positive_rate_pct: number | null;
  fp_rate_by_rule: { rule: string; closed: number; false_positives: number; fp_rate_pct: number }[];
}

export interface Correlation {
  source_ip: string;
  log_rules: string[];
  network_rules: string[];
  alerts: number;
  max_risk: number;
  first_seen: string;
  last_seen: string;
  open_alerts: number;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, { cache: "no-store", ...init });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const body = await res.json();
      msg = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, msg);
  }
  return res.json() as Promise<T>;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

export const api = {
  health: () => call<{ status: string; ollama: boolean }>("/health"),
  uploads: () => call<UploadSummary[]>("/uploads"),
  upload: (id: number) => call<UploadDetail>(`/uploads/${id}`),
  sendFile: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return call<{ upload_id: number }>("/upload-logs", { method: "POST", body: form });
  },
  loadSample: (name: "auth" | "windows" | "pcap") => call<{ upload_id: number }>(`/samples/${name}`, { method: "POST" }),
  alerts: () => call<AlertRow[]>("/alerts"),
  alert: (id: number) => call<AlertDetail>(`/alerts/${id}`),
  triageContext: (rule: string, id: number) => call<TriageContext>(`/playbooks/${rule}?alert_id=${id}`),
  worksheet: (id: number) => call<Worksheet>(`/alerts/${id}/worksheet`),
  saveTriage: (id: number, body: object) => call<{ alert: AlertDetail; worksheet: Worksheet }>(`/alerts/${id}/triage`, json(body)),
  activity: (id: number) => call<Activity[]>(`/alerts/${id}/activity`),
  explain: (id: number) => call<{ text: string; source: string; warnings: string[] }>(`/alerts/${id}/explain`, { method: "POST" }),
  playbooks: () => call<Pick<Playbook, "rule" | "title" | "group" | "summary">[]>("/playbooks"),
  playbook: (rule: string) => call<Playbook>(`/playbooks/${rule}`),
  method: () => call<{ markdown: string }>("/method"),
  metrics: () => call<Metrics>("/metrics"),
  correlations: () => call<Correlation[]>("/correlations"),
  report: (uploadId: number) => call<{ markdown: string }>(`/report/${uploadId}`),
};
