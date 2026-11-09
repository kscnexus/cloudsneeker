import Link from "next/link";
import type { ReactNode } from "react";

import { FOCUS_RING_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { cn } from "@/lib/utils";

export const BAR_TONE = {
  ACCENT: "accent",
  PASS: "pass",
  FAIL: "fail",
  WARNING: "warning",
  NEUTRAL: "neutral",
} as const;

export type BarTone = (typeof BAR_TONE)[keyof typeof BAR_TONE];

const BAR_FILL: Record<BarTone, string> = {
  accent: "bg-button-tertiary",
  pass: "bg-bg-pass",
  fail: "bg-bg-fail",
  warning: "bg-bg-warning",
  neutral: "bg-border-neutral-tertiary",
};

export interface BarListItem {
  id: string;
  label: string;
  /** Shown at the right, e.g. "82%" or "1,204". */
  value: ReactNode;
  /** Bar length, 0-100. */
  percent: number;
  tone?: BarTone;
  /** Second line under the label. */
  hint?: ReactNode;
  href?: string;
}

interface BarListProps {
  items: BarListItem[];
  /** Accessible name of the list. */
  label: string;
  emptyMessage: string;
  className?: string;
}

/** Ranked rows with an inline bar; each row can drill down. */
export const BarList = ({
  items,
  label,
  emptyMessage,
  className,
}: BarListProps) => {
  if (items.length === 0) {
    return (
      <p className="text-text-neutral-tertiary py-2 text-sm">{emptyMessage}</p>
    );
  }
  return (
    <ul aria-label={label} className={cn("flex flex-col gap-1", className)}>
      {items.map((item) => {
        const percent = Math.max(0, Math.min(100, item.percent));
        const content = (
          <>
            <span className="flex items-baseline justify-between gap-3">
              <span className="text-text-neutral-primary min-w-0 truncate text-sm">
                {item.label}
              </span>
              <span className="text-text-neutral-primary shrink-0 text-sm font-semibold tabular-nums">
                {item.value}
              </span>
            </span>
            <span
              aria-hidden="true"
              className="bg-bg-neutral-tertiary block h-1.5 w-full overflow-hidden rounded-full"
            >
              <span
                className={cn(
                  "block h-full rounded-full",
                  BAR_FILL[item.tone ?? BAR_TONE.ACCENT],
                )}
                style={{ width: `${percent}%` }}
              />
            </span>
            {item.hint ? (
              <span className="text-text-neutral-tertiary truncate text-xs">
                {item.hint}
              </span>
            ) : null}
          </>
        );
        return (
          <li key={item.id} className="min-w-0">
            {item.href ? (
              <Link
                href={item.href}
                className={cn(
                  "hover:bg-bg-neutral-tertiary/60 -mx-2 flex flex-col gap-1.5 rounded-lg px-2 py-2 transition-colors",
                  FOCUS_RING_CLASS,
                )}
              >
                {content}
              </Link>
            ) : (
              <div className="flex flex-col gap-1.5 py-2">{content}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
};
