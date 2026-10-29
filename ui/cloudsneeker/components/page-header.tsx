import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export interface PageHeaderMetaItem {
  label: string;
  value: ReactNode;
}

interface PageHeaderProps {
  /** Optional in-page heading; the navbar already shows the page title. */
  title?: string;
  description?: ReactNode;
  /** Buttons or links, aligned right on wide screens. */
  actions?: ReactNode;
  /** Short facts about the record, shown on detail pages. */
  meta?: PageHeaderMetaItem[];
  children?: ReactNode;
  className?: string;
}

export const PageHeader = ({
  title,
  description,
  actions,
  meta,
  children,
  className,
}: PageHeaderProps) => (
  <div
    data-slot="page-header"
    className={cn(
      "mb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between",
      className,
    )}
  >
    <div className="flex max-w-3xl min-w-0 flex-col gap-2">
      {title ? (
        <h2 className="text-text-neutral-primary text-xl font-semibold">
          {title}
        </h2>
      ) : null}
      {description ? (
        <p className="text-text-neutral-secondary text-sm">{description}</p>
      ) : null}
      {meta && meta.length > 0 ? (
        <dl className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
          {meta.map((item) => (
            <div key={item.label} className="flex min-w-0 flex-col gap-0.5">
              <dt className="text-text-neutral-tertiary text-xs font-medium tracking-wide uppercase">
                {item.label}
              </dt>
              <dd className="text-text-neutral-primary break-words">
                {item.value}
              </dd>
            </div>
          ))}
        </dl>
      ) : null}
      {children}
    </div>
    {actions ? (
      <div className="flex flex-wrap items-center gap-2 sm:shrink-0 sm:justify-end">
        {actions}
      </div>
    ) : null}
  </div>
);
