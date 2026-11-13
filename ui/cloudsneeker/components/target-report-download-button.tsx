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
  runWithConcurrency,
  type TargetReportJob,
  type TargetReportProgress,
} from "@/cloudsneeker/lib/target-reports";
import { reportDownloadHref } from "@/cloudsneeker/routes";
import { REPORT_FORMAT, REPORT_RUN_STATUS } from "@/cloudsneeker/types/reports";
import { Button } from "@/components/shadcn";

const START_CONCURRENCY = 4;
const STATUS_BATCH = 50;
const POLL_INTERVAL_MS = 3000;
const DOWNLOAD_GAP_MS = 600;
/** Give up waiting on runs that never finish (stuck worker). */
const MAX_WAIT_MS = 30 * 60 * 1000;

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
    const update = () => setProgress({ total, ready, failed });
    update();

    let downloads = Promise.resolve();
    const queueDownload = (runId: string) => {
      downloads = downloads.then(async () => {
        if (stopRef.current) return;
        triggerDownload(reportDownloadHref(runId, REPORT_FORMAT.PDF));
        await wait(DOWNLOAD_GAP_MS);
      });
    };

    const pending = new Set<string>();
    let lastStartError: string | null = null;
    await runWithConcurrency(
      list,
      START_CONCURRENCY,
      async (job) => {
        const started = await startTargetReport(job.targetId, job.reportType);
        if ("error" in started) {
          failed += 1;
          lastStartError = started.error;
          update();
          return;
        }
        pending.add(started.runId);
      },
      () => stopRef.current,
    );

    const deadline = Date.now() + MAX_WAIT_MS;
    while (pending.size > 0 && !stopRef.current && Date.now() < deadline) {
      await wait(POLL_INTERVAL_MS);
      const ids = Array.from(pending);
      for (let index = 0; index < ids.length; index += STATUS_BATCH) {
        const statuses = await getTargetReportStatuses(
          ids.slice(index, index + STATUS_BATCH),
        );
        for (const [runId, status] of Object.entries(statuses)) {
          if (!isFinishedReportStatus(status)) continue;
          pending.delete(runId);
          if (status === REPORT_RUN_STATUS.COMPLETED) {
            ready += 1;
            queueDownload(runId);
          } else {
            failed += 1;
          }
        }
      }
      update();
    }
    await downloads;

    if (pending.size > 0 && !stopRef.current) {
      failed += pending.size;
      update();
      setError(
        "Some reports are still being prepared. Find them later on the Reports page.",
      );
    } else if (lastStartError && ready === 0) {
      setError(lastStartError);
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
