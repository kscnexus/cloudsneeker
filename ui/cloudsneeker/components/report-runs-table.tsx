"use client";

import { Eye, Trash2 } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { deleteReportRun } from "@/cloudsneeker/actions/reports";
import { reportTitle } from "@/cloudsneeker/lib/report-catalog";
import {
  formatBytes,
  formatReportDate,
  isReportRunActive,
  reportStatusLabel,
  reportStatusTone,
} from "@/cloudsneeker/lib/report-view";
import { reportsHref } from "@/cloudsneeker/routes";
import {
  REPORT_RUN_STATUS,
  type ReportRunResource,
} from "@/cloudsneeker/types/reports";
import { AutoRefresh } from "@/components/scans/auto-refresh";
import { Badge, Button } from "@/components/shadcn";

import { ReportDownloadLinks } from "./report-download-links";
import { ReportShareDialog } from "./report-share-dialog";

interface ReportRunsTableProps {
  runs: ReportRunResource[];
  canShare: boolean;
}

export const ReportRunsTable = ({ runs, canShare }: ReportRunsTableProps) => {
  const router = useRouter();
  const [confirming, setConfirming] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const hasActiveRun = runs.some((run) =>
    isReportRunActive(run.attributes.status),
  );

  const onDelete = async (runId: string) => {
    if (confirming !== runId) {
      setConfirming(runId);
      return;
    }
    setDeleting(runId);
    setError(null);
    const result = await deleteReportRun(runId);
    setDeleting(null);
    setConfirming(null);
    if (result && "error" in result && result.error) {
      setError(
        typeof result.error === "string" ? result.error : "Delete failed.",
      );
      return;
    }
    router.refresh();
  };

  if (runs.length === 0) {
    return (
      <p className="text-text-neutral-secondary border-border-neutral-secondary rounded-xl border border-dashed p-6 text-sm">
        No reports yet. Pick a report above and select Generate.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <AutoRefresh hasExecutingScan={hasActiveRun} />
      {error ? <p className="text-text-error-primary text-sm">{error}</p> : null}
      <div className="border-border-neutral-secondary overflow-x-auto rounded-xl border">
        <table className="w-full text-left text-sm">
          <thead className="bg-bg-neutral-tertiary">
            <tr>
              {["Report", "Status", "Created", "Files", "Actions"].map(
                (header) => (
                  <th
                    key={header}
                    scope="col"
                    className="text-text-neutral-secondary px-3 py-2 text-xs font-semibold"
                  >
                    {header}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody className="divide-border-neutral-secondary divide-y">
            {runs.map((run) => {
              const attributes = run.attributes;
              const name = reportTitle(
                attributes.report_type,
                attributes.report_name,
              );
              const completed =
                attributes.status === REPORT_RUN_STATUS.COMPLETED;
              return (
                <tr key={run.id}>
                  <td className="px-3 py-2">
                    <div className="flex flex-col">
                      {completed ? (
                        <Link
                          href={reportsHref(run.id)}
                          className="text-text-neutral-primary font-medium underline-offset-2 hover:underline"
                        >
                          {name}
                        </Link>
                      ) : (
                        <span className="text-text-neutral-primary font-medium">
                          {name}
                        </span>
                      )}
                      <span className="text-text-neutral-tertiary text-xs">
                        {attributes.trigger === "scheduled"
                          ? "Scheduled"
                          : "On demand"}
                        {attributes.size_bytes
                          ? ` · ${formatBytes(attributes.size_bytes)}`
                          : ""}
                      </span>
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <Badge variant={reportStatusTone(attributes.status)}>
                      {reportStatusLabel(attributes.status)}
                    </Badge>
                    {attributes.status === REPORT_RUN_STATUS.FAILED &&
                    attributes.error ? (
                      <p className="text-text-error-primary mt-1 max-w-xs text-xs">
                        {attributes.error}
                      </p>
                    ) : null}
                  </td>
                  <td className="text-text-neutral-secondary px-3 py-2 text-xs whitespace-nowrap">
                    {formatReportDate(attributes.inserted_at)}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {completed ? (
                        <ReportDownloadLinks
                          runId={run.id}
                          formats={attributes.available_formats ?? []}
                        />
                      ) : (
                        <span className="text-text-neutral-tertiary text-xs">
                          —
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {completed ? (
                        <Button asChild variant="outline" size="xs">
                          <Link href={reportsHref(run.id)}>
                            <Eye aria-hidden="true" />
                            View
                          </Link>
                        </Button>
                      ) : null}
                      {completed && canShare ? (
                        <ReportShareDialog
                          runId={run.id}
                          reportName={name}
                          size="xs"
                        />
                      ) : null}
                      <Button
                        type="button"
                        variant={confirming === run.id ? "destructive" : "ghost"}
                        size="xs"
                        disabled={deleting === run.id}
                        onClick={() => onDelete(run.id)}
                        onBlur={() =>
                          setConfirming((current) =>
                            current === run.id ? null : current,
                          )
                        }
                      >
                        <Trash2 aria-hidden="true" />
                        {confirming === run.id ? "Confirm delete" : "Delete"}
                      </Button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
