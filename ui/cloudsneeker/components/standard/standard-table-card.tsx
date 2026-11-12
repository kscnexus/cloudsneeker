import type { ReactNode } from "react";

import { DataTableSearch } from "@/components/shadcn/table/data-table-search";
import { cn } from "@/lib/utils";

// The container of the Cloud Security Findings table
// (`components/shadcn/table/data-table.tsx`). The `data-table-scroll-container`
// attribute gives it the same frame, pagination row and page buttons from
// `ui/cloudsneeker/styles/surfaces.css`.
export const TABLE_CARD_CLASS =
  "minimal-scrollbar border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full min-w-0 flex-col justify-between gap-4 overflow-auto rounded-[14px] border p-4 shadow-sm";

interface StandardTableCardProps {
  children: ReactNode;
  /** Search box in the toolbar (URL `filter[search]`, Enter to search). */
  searchPlaceholder?: string;
  /** "N Total Entries" on the right of the toolbar. */
  total?: number;
  /** Controls on the right of the toolbar, before the total. */
  toolbarRight?: ReactNode;
  /** Content above the toolbar (for example a selection bar). */
  header?: ReactNode;
  /** Pagination (`PageNav`). */
  footer?: ReactNode;
  className?: string;
}

/** Toolbar (search left, total right), table, pagination: one card. */
export const StandardTableCard = ({
  children,
  searchPlaceholder,
  total,
  toolbarRight,
  header,
  footer,
  className,
}: StandardTableCardProps) => {
  const showToolbar =
    searchPlaceholder !== undefined ||
    total !== undefined ||
    toolbarRight !== undefined;
  return (
    <div data-table-scroll-container="" className={cn(TABLE_CARD_CLASS, className)}>
      {header ? <div className="w-full">{header}</div> : null}
      {showToolbar ? (
        <div
          data-testid="data-table-toolbar"
          className="flex flex-col items-start gap-3 md:flex-row md:items-center md:justify-between"
        >
          <div className="w-full md:w-auto">
            {searchPlaceholder !== undefined ? (
              <DataTableSearch placeholder={searchPlaceholder} />
            ) : null}
          </div>
          <div className="flex w-full flex-wrap items-center gap-x-4 gap-y-2 md:ml-auto md:w-auto">
            {toolbarRight}
            {total !== undefined ? (
              <span className="text-text-neutral-secondary text-sm whitespace-nowrap">
                {total.toLocaleString()} Total Entries
              </span>
            ) : null}
          </div>
        </div>
      ) : null}
      {children}
      {footer ?? null}
    </div>
  );
};
