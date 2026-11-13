"use client";

import { Download } from "lucide-react";
import { useRef, useState } from "react";

import {
  getTargetReportStatuses,
  listRepositoryReportJobs,
  startTargetReport,
} from "@/cloudsneeker/actions/target-reports";
import {
  describeReportProgress,
  isFinishedReportStatus,
  type TargetReportJob,
  type TargetReportProgress,
} from "@/cloudsneeker/lib/target-reports";
import { reportDownloadHref } from "@/cloudsneeker/routes";
import {
  REPORT_FORMAT,
  REPORT_RUN_STATUS,
  type ReportRunStatus,
} from "@/cloudsneeker/types/reports";
import { Button } from "@/components/shadcn";

const POLL_INTERVAL_MS = 3000;
/** Pause between reports so a long batch never floods the API or database. */
const JOB_GAP_MS = 1000;
/** Give up on a run that never finishes (stuck worker) and move on. */
const MAX_WAIT_PER_RUN_MS = 10 * 60 * 1000;
const MAX_FAILED_NAMES = 5;

const wait = (ms: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, ms);
  });

/** The API's Content-Disposition names the file after the target. */
const triggerDownload = (href: string) => {
  const anchor = document.createElement("a");
  anchor.href = href;
  anchor.download = "";
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
};

interface TargetReportDownloadButtonProps {
  label: string;
  /** Jobs to run; omit to load every repository and SAST target on click. */
  jobs?: TargetReportJob[];
  variant?: "default" | "outline" | "ghost";
}

export const TargetReportDownloadButton = ({
  label,
  jobs,
  variant = "outline",
}: TargetReportDownloadButtonProps) => {
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<TargetReportProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const stopRef = useRef(false);

  const run = async () => {
    setError(null);
    setProgress(null);
    let list = jobs;
    if (!list) {
      setRunning(true);
      const loaded = await listRepositoryReportJobs();
      if ("error" in loaded) {
        setRunning(false);
        setError(loaded.error);
        return;
      }
      list = loaded.jobs;
    }
    if (list.length === 0) {
      setRunning(false);
      setError("No repository or SAST targets to report on yet.");
      return;
    }
    if (
      list.length > 1 &&
      !window.confirm(
        `Generate and download ${list.length} PDF reports, one per target? Keep this page open; your browser may ask to allow multiple downloads.`,
      )
    ) {
      setRunning(false);
      return;
    }

    stopRef.current = false;
    setRunning(true);
    const total = list.length;
    let ready = 0;
    let failed = 0;
    const failedNames: string[] = [];
    let lastError: string | null = null;
    const update = () => setProgress({ total, ready, failed });
    update();

    const markFailed = (job: TargetReportJob, reason: string | null) => {
      failed += 1;
      failedNames.push(job.targetName);
      if (reason) lastError = reason;
      update();
    };

    // One report at a time: start it, wait for it, download it, then move
    // on. Bulk runs of hundreds of targets stay within the database's
    // connection limit this way.
    for (const job of list) {
      if (stopRef.current) break;
      const started = await startTargetReport(job.targetId, job.reportType);
      if ("error" in started) {
        markFailed(job, started.error);
        await wait(JOB_GAP_MS);
        continue;
      }
      const deadline = Date.now() + MAX_WAIT_PER_RUN_MS;
      let status: ReportRunStatus = REPORT_RUN_STATUS.PENDING;
      while (
        !isFinishedReportStatus(status) &&
        !stopRef.current &&
        Date.now() < deadline
      ) {
        await wait(POLL_INTERVAL_MS);
        const statuses = await getTargetReportStatuses([started.runId]);
        status = statuses[started.runId] ?? REPORT_RUN_STATUS.FAILED;
      }
      if (status === REPORT_RUN_STATUS.COMPLETED) {
        ready += 1;
        update();
        triggerDownload(reportDownloadHref(started.runId, REPORT_FORMAT.PDF));
      } else if (!stopRef.current) {
        markFailed(job, null);
      }
      await wait(JOB_GAP_MS);
    }

    if (failedNames.length > 0) {
      const shown = failedNames.slice(0, MAX_FAILED_NAMES).join(", ");
      const more =
        failedNames.length > MAX_FAILED_NAMES
          ? ` and ${failedNames.length - MAX_FAILED_NAMES} more`
          : "";
      setError(
        `${lastError && ready === 0 ? `${lastError} ` : ""}Not downloaded: ${shown}${more}.`,
      );
    }
    setRunning(false);
  };

  const stop = () => {
    stopRef.current = true;
  };

  return (
    <div className="flex flex-col items-end gap-1">
      {running ? (
        <Button type="button" size="sm" variant="ghost" onClick={stop}>
          Stop
        </Button>
      ) : (
        <Button type="button" size="sm" variant={variant} onClick={run}>
          <Download aria-hidden="true" />
          {label}
        </Button>
      )}
      {progress ? (
        <span
          className="text-text-neutral-secondary text-xs"
          role="status"
          aria-live="polite"
        >
          {describeReportProgress(progress)}
        </span>
      ) : null}
      {error ? (
        <span className="text-text-error-primary text-xs" role="alert">
          {error}
        </span>
      ) : null}
    </div>
  );
};
