import Link from "next/link";
import type { ReactNode } from "react";

import {
  appSecPriorityLabel,
  appSecSeverityLabel,
  appSecStateLabel,
} from "@/cloudsneeker/lib/appsec";
import { Button } from "@/components/shadcn";
import { Badge } from "@/components/shadcn/badge/badge";
import { cn } from "@/lib/utils";

import { EmptyState } from "./empty-state";
import { PageNav } from "./page-nav";
import { SectionCard } from "./section-card";

const SEVERITY_CLASS: Record<string, string> = {
  critical: "bg-bg-data-critical text-white",
  high: "bg-bg-data-high text-black",
  medium: "bg-bg-data-medium text-black",
  low: "bg-bg-data-low text-black",
  informational: "bg-bg-data-info text-white",
};

/** Scanner severity pill; "unknown" stays neutral instead of reading as low. */
export const AppSecSeverityBadge = ({ severity }: { severity: string }) => (
  <span
    className={cn(
      "inline-flex rounded-full px-2 py-0.5 text-xs font-semibold whitespace-nowrap",
      SEVERITY_CLASS[severity] ??
        "bg-bg-neutral-tertiary text-text-neutral-primary",
    )}
  >
    {appSecSeverityLabel(severity)}
  </span>
);

const STATE_VARIANT = {
  new: "info",
  open: "warning",
  reopened: "error",
  fixed: "success",
} as const;

export const AppSecStateBadge = ({ state }: { state: string }) => (
  <Badge variant={STATE_VARIANT[state as keyof typeof STATE_VARIANT] ?? "tag"}>
    {appSecStateLabel(state)}
  </Badge>
);

const PRIORITY_CLASS: Record<string, string> = {
  urgent: "border-bg-data-critical text-text-neutral-primary",
  high: "border-bg-data-high text-text-neutral-primary",
  medium: "border-bg-data-medium text-text-neutral-secondary",
  low: "border-border-neutral-secondary text-text-neutral-tertiary",
};

/** Calculated priority with its score, visually distinct from severity. */
export const AppSecPriorityBadge = ({
  priority,
  score,
}: {
  priority: string;
  score?: number;
}) => (
  <span
    className={cn(
      "inline-flex items-center gap-1 rounded-md border-l-4 px-2 py-0.5 text-xs font-medium whitespace-nowrap",
      PRIORITY_CLASS[priority] ?? PRIORITY_CLASS.low,
    )}
  >
    {appSecPriorityLabel(priority)}
    {score !== undefined ? (
      <span className="text-text-neutral-tertiary tabular-nums">{score}</span>
    ) : null}
  </span>
);

interface ChipLinkProps {
  href: string;
  active: boolean;
  children: ReactNode;
}

/** Filter chip rendered as a link, so filters work without client code. */
export const ChipLink = ({ href, active, children }: ChipLinkProps) => (
  <Link
    href={href}
    aria-current={active ? "true" : undefined}
    className={cn(
      "rounded-full border px-3 py-1 text-xs font-medium whitespace-nowrap transition-colors",
      active
        ? "border-button-primary bg-button-primary text-black"
        : "border-border-neutral-secondary text-text-neutral-secondary hover:text-text-neutral-primary",
    )}
  >
    {children}
  </Link>
);

export const TABLE_WRAPPER_CLASS =
  "border-border-neutral-secondary min-w-0 overflow-x-auto rounded-lg border";
export const TABLE_CLASS = "w-full min-w-[720px] text-left text-sm";
export const TH_CLASS =
  "bg-bg-neutral-tertiary text-text-neutral-secondary px-3 py-2 text-xs font-semibold tracking-wide whitespace-nowrap uppercase";
export const TD_CLASS =
  "border-border-neutral-secondary text-text-neutral-secondary border-t px-3 py-2 align-top";
export const TD_PRIMARY_CLASS =
  "border-border-neutral-secondary text-text-neutral-primary border-t px-3 py-2 align-top";
export const ROW_LINK_CLASS =
  "text-text-neutral-primary font-medium hover:underline focus-visible:underline focus-visible:outline-none";

interface PagerProps {
  page: number;
  pages: number;
  hrefFor: (page: number) => string;
  count?: number;
  noun?: string;
}

/** Numbered pagination (see `PageNav`). */
export const Pager = ({ page, pages, hrefFor, count, noun }: PagerProps) =>
  pages > 1 ? (
    <PageNav
      page={page}
      pages={pages}
      hrefFor={hrefFor}
      count={count}
      noun={noun}
    />
  ) : null;

interface LoadErrorProps {
  title: string;
  what: string;
  reloadHref: string;
}

/** A failed request must not read as "nothing here yet". */
export const LoadError = ({ title, what, reloadHref }: LoadErrorProps) => (
  <SectionCard title={title}>
    <EmptyState
      title={`${what} could not be loaded`}
      description="The service did not answer. Reload the page in a moment."
      action={
        <Button asChild size="sm" variant="outline">
          <Link href={reloadHref}>Reload</Link>
        </Button>
      }
    />
  </SectionCard>
);

interface CountBarItem {
  key: string;
  label: string;
  count: number;
  href?: string;
  className?: string;
}

/** Horizontal bars for a small distribution (counts by ecosystem, state). */
export const CountBars = ({ items }: { items: CountBarItem[] }) => {
  const max = Math.max(1, ...items.map((item) => item.count));
  return (
    <ul className="flex flex-col gap-2">
      {items.map((item) => {
        const label = (
          <span className="text-text-neutral-primary truncate text-sm">
            {item.label}
          </span>
        );
        return (
          <li key={item.key} className="flex items-center gap-3">
            <div className="w-36 min-w-0 shrink-0">
              {item.href ? (
                <Link href={item.href} className="hover:underline">
                  {label}
                </Link>
              ) : (
                label
              )}
            </div>
            <div
              className="bg-bg-neutral-tertiary h-2 min-w-0 flex-1 overflow-hidden rounded-full"
              aria-hidden="true"
            >
              <div
                className={cn(
                  "h-full rounded-full",
                  item.className ?? "bg-button-tertiary",
                )}
                style={{ width: `${(item.count / max) * 100}%` }}
              />
            </div>
            <span className="text-text-neutral-secondary w-12 shrink-0 text-right text-sm tabular-nums">
              {item.count}
            </span>
          </li>
        );
      })}
    </ul>
  );
};

export const SEVERITY_BAR_CLASS: Record<string, string> = {
  critical: "bg-bg-data-critical",
  high: "bg-bg-data-high",
  medium: "bg-bg-data-medium",
  low: "bg-bg-data-low",
  informational: "bg-bg-data-info",
  unknown: "bg-border-neutral-tertiary",
};
