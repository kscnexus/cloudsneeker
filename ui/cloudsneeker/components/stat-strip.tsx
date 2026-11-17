import Link from "next/link";

import { FOCUS_RING_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { cn } from "@/lib/utils";

export interface StatStripItem {
  label: string;
  value: number | string;
  /** Explains the number; shown as a tooltip and read by screen readers. */
  hint?: string;
  /** Makes the stat a drill-down link. */
  href?: string;
}

interface StatStripProps {
  /** Accessible name of the group. */
  label: string;
  items: StatStripItem[];
  className?: string;
}

const ITEM_CLASS = "flex min-w-0 flex-col gap-0.5";

/**
 * Supporting numbers in one compact row, for detail that does not need a
 * `StatTile` each. Keeps the list or table below it above the fold.
 */
export const StatStrip = ({ label, items, className }: StatStripProps) => (
  <ul
    aria-label={label}
    data-slot="stat-strip"
    className={cn(
      "border-border-neutral-secondary bg-bg-neutral-secondary grid grid-cols-2 gap-x-6 gap-y-3 rounded-xl border px-4 py-3 sm:grid-cols-3 sm:px-5 lg:grid-cols-5",
      className,
    )}
  >
    {items.map((item) => {
      const body = (
        <>
          <span className="text-text-neutral-tertiary text-xs">
            {item.label}
          </span>
          <span className="text-text-neutral-primary text-base font-semibold tabular-nums">
            {item.value}
          </span>
          {item.hint ? <span className="sr-only">{item.hint}</span> : null}
        </>
      );
      return (
        <li key={item.label} title={item.hint} className="min-w-0">
          {item.href ? (
            <Link
              href={item.href}
              aria-label={`${item.label}: ${item.value}`}
              className={cn(
                ITEM_CLASS,
                "rounded-md hover:underline",
                FOCUS_RING_CLASS,
              )}
            >
              {body}
            </Link>
          ) : (
            <div className={ITEM_CLASS}>{body}</div>
          )}
        </li>
      );
    })}
  </ul>
);
