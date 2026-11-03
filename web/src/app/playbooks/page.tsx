"use client";

import { ChevronDown, ChevronRight, FileText, Network } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";
import { Markdown } from "@/components/markdown";
import { Card, ErrorBox, PageHeader, Spinner } from "@/components/ui";
import { api, type Playbook } from "@/lib/api";
import { cn } from "@/lib/utils";

type Summary = Pick<Playbook, "rule" | "title" | "group" | "summary">;

export default function PlaybooksPage() {
  const [books, setBooks] = useState<Summary[] | null>(null);
  const [method, setMethod] = useState("");
  const [open, setOpen] = useState(true);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    Promise.all([api.playbooks(), api.method()]).then(([b, m]) => { setBooks(b); setMethod(m.markdown); }).catch(setError);
  }, []);

  if (error) return <ErrorBox error={error} />;
  if (!books) return <Spinner />;

  return (
    <div className="space-y-5">
      <PageHeader title="Triage playbooks" subtitle="How an L1 analyst decides True or False Positive: the method, then one playbook per alert type." />

      <Card>
        <button onClick={() => setOpen((v) => !v)} className="flex w-full items-center justify-between text-left" aria-expanded={open}>
          <span className="text-[0.95rem] font-semibold">The triage method · the 5 Ws</span>
          <ChevronDown className={cn("size-4 text-muted transition", open && "rotate-180")} />
        </button>
        {open && <div className="mt-2"><Markdown>{method.replace(/^###.*\n/, "")}</Markdown></div>}
      </Card>

      {(["Logs", "Network"] as const).map((group) => (
        <section key={group}>
          <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-muted">
            {group === "Logs" ? <FileText className="size-4" /> : <Network className="size-4" />}
            {group === "Logs" ? "Log alerts" : "Network (packet capture) alerts"}
          </h2>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {books.filter((b) => b.group === group).sort((a, b) => a.title.localeCompare(b.title)).map((b) => (
              <Link key={b.rule} href={`/playbooks/${b.rule}`}
                    className="group rounded-2xl border border-line bg-surface p-4 shadow-sm transition hover:border-accent">
                <div className="flex items-start justify-between gap-2">
                  <p className="font-semibold leading-snug">{b.title}</p>
                  <ChevronRight className="size-4 shrink-0 text-muted group-hover:text-accent" />
                </div>
                <p className="mt-1.5 line-clamp-3 text-sm text-muted">{b.summary}</p>
              </Link>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}
