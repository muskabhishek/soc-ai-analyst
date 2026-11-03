"use client";

import { Monitor, Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";

const OPTIONS = [
  { value: "light", icon: Sun, label: "Light" },
  { value: "system", icon: Monitor, label: "System" },
  { value: "dark", icon: Moon, label: "Dark" },
] as const;

export function ThemeToggle({ compact }: { compact?: boolean }) {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  // eslint-disable-next-line react-hooks/set-state-in-effect -- standard next-themes hydration guard
  useEffect(() => setMounted(true), []);
  const current = mounted ? theme : "system";

  return (
    <div role="radiogroup" aria-label="Theme" className="inline-flex rounded-xl border border-line bg-subtle p-0.5">
      {OPTIONS.map(({ value, icon: Icon, label }) => (
        <button
          key={value}
          role="radio"
          aria-checked={current === value}
          aria-label={label}
          title={label}
          onClick={() => setTheme(value)}
          className={cn(
            "flex items-center gap-1.5 rounded-[10px] px-2 py-1 text-xs font-medium text-muted transition",
            current === value && "bg-surface text-ink shadow-sm",
          )}
        >
          <Icon className="size-3.5" />
          {!compact && label}
        </button>
      ))}
    </div>
  );
}
