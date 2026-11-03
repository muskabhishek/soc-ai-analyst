"use client";

import { BookOpen, FolderKanban, LayoutDashboard, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";
import { api } from "@/lib/api";
import { cn, getAnalyst, setAnalyst } from "@/lib/utils";
import { ThemeToggle } from "./theme-toggle";

const NAV = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/cases", label: "Cases", icon: FolderKanban },
  { href: "/playbooks", label: "Playbooks", icon: BookOpen },
];

function isActive(path: string, href: string) {
  return href === "/" ? path === "/" || path.startsWith("/alerts") || path.startsWith("/report") : path.startsWith(href);
}

function Brand() {
  return (
    <Link href="/" className="flex items-center gap-2.5">
      <span className="grid size-9 place-items-center rounded-xl bg-gradient-to-br from-blue-600 to-cyan-500 text-white shadow-sm">
        <ShieldCheck className="size-5" />
      </span>
      <span className="leading-tight">
        <span className="block text-sm font-bold tracking-tight">SOC Analyst</span>
        <span className="block text-[0.7rem] text-muted">AI-assisted triage</span>
      </span>
    </Link>
  );
}

function Status() {
  const [state, setState] = useState<"up" | "down" | "checking">("checking");
  const [ollama, setOllama] = useState(false);
  useEffect(() => {
    api.health().then((h) => { setState("up"); setOllama(h.ollama); }).catch(() => setState("down"));
  }, []);
  return (
    <div className="space-y-1.5 text-xs text-muted">
      <p className="flex items-center gap-2">
        <span className={cn("size-2 rounded-full", state === "up" ? "bg-low" : state === "down" ? "bg-crit" : "bg-med")} />
        API {state === "up" ? "connected" : state === "down" ? "offline" : "…"}
      </p>
      <p className="flex items-center gap-2">
        <span className={cn("size-2 rounded-full", ollama ? "bg-low" : "bg-muted/50")} />
        {ollama ? "Local LLM on" : "LLM off: template reports"}
      </p>
    </div>
  );
}

function AnalystField() {
  const [name, setName] = useState("analyst1");
  // eslint-disable-next-line react-hooks/set-state-in-effect -- read the saved name once, after hydration
  useEffect(() => setName(getAnalyst()), []);
  return (
    <label className="block text-xs text-muted">
      Analyst
      <input
        value={name}
        onChange={(e) => { setName(e.target.value); setAnalyst(e.target.value); }}
        className="mt-1 w-full rounded-lg border border-line bg-surface px-2.5 py-1.5 text-sm text-ink outline-none focus:border-accent"
      />
    </label>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const path = usePathname();
  return (
    <div className="min-h-dvh lg:grid lg:grid-cols-[248px_1fr]">
      {/* desktop sidebar */}
      <div className="no-print hidden border-r border-line bg-surface lg:block">
      <aside className="sticky top-0 flex h-dvh flex-col gap-6 px-4 py-5">
        <Brand />
        <nav className="flex flex-col gap-1">
          {NAV.map(({ href, label, icon: Icon }) => (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium text-muted transition hover:bg-subtle hover:text-ink",
                isActive(path, href) && "bg-accent-soft text-accent hover:bg-accent-soft hover:text-accent",
              )}
            >
              <Icon className="size-4" /> {label}
            </Link>
          ))}
        </nav>
        <div className="mt-auto space-y-4">
          <AnalystField />
          <Status />
          <ThemeToggle />
        </div>
      </aside>
      </div>

      {/* mobile top bar */}
      <header className="no-print sticky top-0 z-20 flex items-center justify-between border-b border-line bg-surface/85 px-4 py-3 backdrop-blur lg:hidden">
        <Brand />
        <ThemeToggle compact />
      </header>

      <main className="mx-auto w-full max-w-7xl px-4 pb-28 pt-5 sm:px-6 lg:px-8 lg:pb-10 lg:pt-8">{children}</main>

      {/* mobile bottom tabs */}
      <nav className="no-print fixed inset-x-0 bottom-0 z-20 grid grid-cols-3 border-t border-line bg-surface/95 pb-[env(safe-area-inset-bottom)] backdrop-blur lg:hidden">
        {NAV.map(({ href, label, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className={cn("flex flex-col items-center gap-0.5 py-2.5 text-[0.7rem] font-medium text-muted", isActive(path, href) && "text-accent")}
          >
            <Icon className="size-5" />
            {label}
          </Link>
        ))}
      </nav>
    </div>
  );
}
