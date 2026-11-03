"use client";

import { FileText, Network, ScrollText, UploadCloud } from "lucide-react";
import { useRef, useState } from "react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Button, ErrorBox } from "./ui";

const SAMPLES = [
  { name: "auth", label: "Linux SSH log", icon: ScrollText },
  { name: "windows", label: "Windows events", icon: FileText },
  { name: "pcap", label: "Packet capture", icon: Network },
] as const;

export function UploadPanel({ onDone, compact }: { onDone: (uploadId: number) => void; compact?: boolean }) {
  const input = useRef<HTMLInputElement>(null);
  const [drag, setDrag] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  async function run(label: string, job: () => Promise<{ upload_id: number }>) {
    setBusy(label);
    setError(null);
    try {
      onDone((await job()).upload_id);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  }

  const sendFile = (f?: File | null) => f && run(f.name, () => api.sendFile(f));

  return (
    <div className="space-y-3">
      <div
        role="button"
        tabIndex={0}
        onClick={() => input.current?.click()}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); sendFile(e.dataTransfer.files?.[0]); }}
        className={cn(
          "flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed border-line bg-subtle/60 text-center transition",
          "hover:border-accent hover:bg-accent-soft/40 focus-visible:outline-2 focus-visible:outline-accent",
          compact ? "px-4 py-5" : "px-6 py-10",
          drag && "border-accent bg-accent-soft/50",
        )}
      >
        <UploadCloud className={cn("text-accent", compact ? "size-6" : "size-9")} />
        <p className="mt-2 text-sm font-semibold">
          {busy ? `Analysing ${busy}…` : "Drop a file here or tap to upload"}
        </p>
        <p className="mt-1 text-xs text-muted">Linux auth.log · Windows Security CSV · Wireshark .pcap / .pcapng</p>
        <input
          ref={input}
          type="file"
          className="hidden"
          accept=".log,.txt,.csv,.pcap,.pcapng,.cap"
          onChange={(e) => { sendFile(e.target.files?.[0]); e.target.value = ""; }}
        />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted">Or try a sample with hidden attacks:</span>
        {SAMPLES.map(({ name, label, icon: Icon }) => (
          <Button key={name} className="py-1.5 text-xs" loading={busy === label} disabled={!!busy}
                  onClick={() => run(label, () => api.loadSample(name))}>
            <Icon className="size-3.5" /> {label}
          </Button>
        ))}
      </div>
      {error != null && <ErrorBox error={error} />}
    </div>
  );
}
