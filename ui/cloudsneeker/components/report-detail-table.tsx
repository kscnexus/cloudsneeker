"use client";

import { useState } from "react";

import {
  formatCell,
  pageCount,
  pageRows,
  REPORT_DETAIL_PAGE_SIZE,
} from "@/cloudsneeker/lib/report-view";
import type { ReportTable } from "@/cloudsneeker/types/reports";
import { Button } from "@/components/shadcn";

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
    <section className="flex flex-col gap-3 break-inside-avoid-page">
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
        <div className="border-border-neutral-secondary overflow-x-auto rounded-xl border print:overflow-visible">
          <table className="w-full text-left text-sm">
            <thead className="bg-bg-neutral-tertiary">
              <tr>
                {table.columns.map((column) => (
                  <th
                    key={column.field}
                    scope="col"
                    className="text-text-neutral-secondary px-3 py-2 text-xs font-semibold whitespace-nowrap"
                  >
                    {column.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-border-neutral-secondary divide-y">
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
        <div className="flex items-center justify-end gap-2 print:hidden">
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={current <= 1}
            onClick={() => setPage(current - 1)}
          >
            Previous
          </Button>
          <span className="text-text-neutral-secondary text-xs">
            Page {current} of {pages}
          </span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={current >= pages}
            onClick={() => setPage(current + 1)}
          >
            Next
          </Button>
        </div>
      ) : null}
    </section>
  );
};
