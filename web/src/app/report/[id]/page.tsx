"use client";

import { ArrowLeft, Download, Printer } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { Markdown } from "@/components/markdown";
import { Button, Card, ErrorBox, PageHeader, Spinner } from "@/components/ui";
import { api } from "@/lib/api";

export default function ReportPage() {
  const id = Number(useParams<{ id: string }>().id);
  const [md, setMd] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => { api.report(id).then((r) => setMd(r.markdown)).catch(setError); }, [id]);

  if (error) return <ErrorBox error={error} />;
  if (md == null) return <Spinner label="Writing the report" />;

  const download = () => {
    const url = URL.createObjectURL(new Blob([md], { type: "text/markdown" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: `incident-report-${id}.md` });
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      <Link href={`/?upload=${id}`} className="no-print inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink">
        <ArrowLeft className="size-4" /> Back to overview
      </Link>
      <PageHeader
        title="Incident report"
        subtitle="Every alert with its analysis, ready for escalation"
        actions={
          <div className="no-print flex gap-2">
            <Button onClick={download}><Download className="size-4" /> Markdown</Button>
            <Button onClick={() => window.print()}><Printer className="size-4" /> Print / PDF</Button>
          </div>
        }
      />
      <Card className="mx-auto max-w-4xl"><Markdown>{md}</Markdown></Card>
    </div>
  );
}
