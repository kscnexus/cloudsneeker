import {
  ChevronFirst,
  ChevronLast,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { PAGE_GAP, pageWindow } from "@/cloudsneeker/lib/page-window";
import { cn } from "@/lib/utils";

// Matches the Cloud Security tables' pagination (DataTablePagination).
const NAV_CLASS = {
  base: "flex size-8 items-center justify-center rounded-full text-xs font-medium transition-colors",
  enabled:
    "text-text-neutral-secondary hover:bg-bg-neutral-tertiary hover:text-text-neutral-primary",
  current: "bg-bg-neutral-tertiary text-text-neutral-primary",
  disabled: "text-text-neutral-tertiary pointer-events-none",
} as const;

interface PageNavProps {
  page: number;
  pages: number;
  /** Total items, shown as "N noun". */
  count?: number;
  noun?: string;
  /** Link for a page (server pages); or use `onSelect` in client tables. */
  hrefFor?: (page: number) => string;
  onSelect?: (page: number) => void;
}

interface PageControlProps {
  target: number;
  label: string;
  disabled?: boolean;
  current?: boolean;
  hrefFor?: (page: number) => string;
  onSelect?: (page: number) => void;
  children: ReactNode;
}

const PageControl = ({
  target,
  label,
  disabled = false,
  current = false,
  hrefFor,
  onSelect,
  children,
}: PageControlProps) => {
  const className = cn(
    NAV_CLASS.base,
    current
      ? NAV_CLASS.current
      : disabled
        ? NAV_CLASS.disabled
        : NAV_CLASS.enabled,
  );
  if (disabled || current || (!hrefFor && !onSelect)) {
    return (
      <span
        className={className}
        aria-label={label}
        aria-current={current ? "page" : undefined}
        aria-disabled={disabled || undefined}
      >
        {children}
      </span>
    );
  }
  if (hrefFor) {
    return (
      <Link href={hrefFor(target)} className={className} aria-label={label}>
        {children}
      </Link>
    );
  }
  return (
    <button
      type="button"
      className={className}
      aria-label={label}
      onClick={() => onSelect?.(target)}
    >
      {children}
    </button>
  );
};

/** "N items · Page X of Y", first/previous, numbered pages, next/last. */
export const PageNav = ({
  page,
  pages,
  count,
  noun = "items",
  hrefFor,
  onSelect,
}: PageNavProps) => {
  if (pages <= 1 && count === undefined) return null;
  const current = Math.min(Math.max(page, 1), Math.max(pages, 1));
  const first = current <= 1;
  const last = current >= pages;
  const link = { hrefFor, onSelect };

  return (
    <nav
      aria-label={`${noun} pages`}
      className="text-text-neutral-secondary flex flex-wrap items-center justify-between gap-3 py-1.5 text-xs font-medium"
    >
      <span>
        {count !== undefined ? `${count} ${noun}` : null}
        {count !== undefined && pages > 1 ? " · " : null}
        {pages > 1 ? `Page ${current} of ${pages}` : null}
      </span>
      {pages > 1 ? (
        <div className="flex flex-wrap items-center gap-1">
          <PageControl
            target={1}
            label="Go to first page"
            disabled={first}
            {...link}
          >
            <ChevronFirst className="size-4" aria-hidden="true" />
          </PageControl>
          <PageControl
            target={current - 1}
            label="Go to previous page"
            disabled={first}
            {...link}
          >
            <ChevronLeft className="size-4" aria-hidden="true" />
          </PageControl>
          {pageWindow(current, pages).map((item, index) =>
            item === PAGE_GAP ? (
              <span
                key={`gap-${index}`}
                className="text-text-neutral-tertiary px-1"
                aria-hidden="true"
              >
                …
              </span>
            ) : (
              <PageControl
                key={item}
                target={item}
                label={`Page ${item}`}
                current={item === current}
                {...link}
              >
                {item}
              </PageControl>
            ),
          )}
          <PageControl
            target={current + 1}
            label="Go to next page"
            disabled={last}
            {...link}
          >
            <ChevronRight className="size-4" aria-hidden="true" />
          </PageControl>
          <PageControl
            target={pages}
            label="Go to last page"
            disabled={last}
            {...link}
          >
            <ChevronLast className="size-4" aria-hidden="true" />
          </PageControl>
        </div>
      ) : null}
    </nav>
  );
};
