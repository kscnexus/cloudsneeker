"use client";

import { useState } from "react";

import {
  formatCell,
  pageCount,
  pageRows,
  REPORT_DETAIL_PAGE_SIZE,
} from "@/cloudsneeker/lib/report-view";
import {
  TABLE_BODY_CLASS,
  TABLE_CLASS,
  TABLE_FRAME_CLASS,
  TABLE_HEADER_CELL_CLASS,
  TABLE_HEAD_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import type { ReportTable } from "@/cloudsneeker/types/reports";
import { cn } from "@/lib/utils";

import { PageNav } from "./page-nav";
import { ReportSeverityBadge } from "./report-severity-badge";

interface ReportDetailTableProps {
  table: ReportTable;
  pageSize?: number;
}

export const ReportDetailTable = ({
  table,
  pageSize = REPORT_DETAIL_PAGE_SIZE,
}: ReportDetailTableProps) => {
  const [page, setPage] = useState(1);
  const pages = pageCount(table.rows.length, pageSize);
  const current = Math.min(page, pages);
  const rows = pageRows(table.rows, current, pageSize);

  return (
    <section className="flex break-inside-avoid-page flex-col gap-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-text-neutral-primary text-base font-semibold">
          {table.title}
        </h3>
        <p className="text-text-neutral-tertiary text-xs">
          {table.truncated
            ? `Showing ${table.rows.length.toLocaleString("en-US")} of ${table.total.toLocaleString("en-US")} rows. Download the spreadsheet for every row.`
            : `${table.total.toLocaleString("en-US")} rows`}
        </p>
      </div>
      {table.rows.length === 0 ? (
        <p className="text-text-neutral-secondary text-sm">Nothing to list.</p>
      ) : (
        <div className={cn(TABLE_FRAME_CLASS, "print:overflow-visible")}>
          <table className={TABLE_CLASS}>
            <thead className={TABLE_HEAD_CLASS}>
              <tr>
                {table.columns.map((column) => (
                  <th
                    key={column.field}
                    scope="col"
                    className={TABLE_HEADER_CELL_CLASS}
                  >
                    {column.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className={TABLE_BODY_CLASS}>
              {rows.map((row, index) => (
                <tr key={`${table.key}-${(current - 1) * pageSize + index}`}>
                  {table.columns.map((column) => (
                    <td
                      key={column.field}
                      className="text-text-neutral-primary max-w-md px-3 py-2 align-top break-words"
                    >
                      {column.field === "severity" &&
                      typeof row[column.field] === "string" ? (
                        <ReportSeverityBadge
                          severity={String(row[column.field])}
                        />
                      ) : (
                        formatCell(row[column.field])
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {pages > 1 ? (
        <div className="print:hidden">
          <PageNav
            page={current}
            pages={pages}
            noun="rows"
            onSelect={setPage}
          />
        </div>
      ) : null}
    </section>
  );
};
