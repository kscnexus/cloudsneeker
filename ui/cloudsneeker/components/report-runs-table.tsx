"use client";

import { Eye, FileText, Trash2 } from "lucide-react";
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
import {
  TABLE_BODY_CLASS,
  TABLE_CLASS,
  TABLE_FRAME_CLASS,
  TABLE_HEADER_CELL_CLASS,
  TABLE_HEAD_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import { reportsHref } from "@/cloudsneeker/routes";
import {
  REPORT_RUN_STATUS,
  type ReportRunResource,
} from "@/cloudsneeker/types/reports";
import { AutoRefresh } from "@/components/scans/auto-refresh";
import { Badge, Button } from "@/components/shadcn";

import { EmptyState } from "./empty-state";
import { FormAlert } from "./form-layout";
import { ReportDownloadLinks } from "./report-download-links";
import { ReportShareDialog } from "./report-share-dialog";

interface ReportRunsTableProps {
  runs: ReportRunResource[];
  canShare: boolean;
  /** Filters are applied: an empty list means "no match", not "none yet". */
  filtered?: boolean;
}

export const ReportRunsTable = ({
  runs,
  canShare,
  filtered = false,
}: ReportRunsTableProps) => {
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
      <EmptyState
        icon={<FileText />}
        title={filtered ? "No reports match" : "No reports yet"}
        description={
          filtered
            ? "Clear a filter to see more reports."
            : "Pick a report above and select Generate."
        }
      />
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <AutoRefresh hasExecutingScan={hasActiveRun} />
      <FormAlert message={error} />
      <div className={TABLE_FRAME_CLASS}>
        <table className={TABLE_CLASS}>
          <thead className={TABLE_HEAD_CLASS}>
            <tr>
              {["Report", "Status", "Created", "Files", "Actions"].map(
                (header) => (
                  <th
                    key={header}
                    scope="col"
                    className={TABLE_HEADER_CELL_CLASS}
                  >
                    {header}
                  </th>
                ),
              )}
            </tr>
          </thead>
          <tbody className={TABLE_BODY_CLASS}>
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
                        variant={
                          confirming === run.id ? "destructive" : "ghost"
                        }
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
