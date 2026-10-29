import Link from "next/link";

import {
  findingsHrefForScan,
  labelForTrivyMode,
} from "@/cloudsneeker/lib/trivy-modes";
import { CARD_LIST_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type { TrivyRunResource } from "@/cloudsneeker/types/trivy";

import { RunStatusBadge } from "./run-status-badge";

interface AppSecurityRunListProps {
  runs: TrivyRunResource[];
  /** Show the target name (hub) or the status as the row title (target page). */
  showTarget?: boolean;
  emptyMessage?: string;
}

const formatRunTime = (value: string | null | undefined): string => {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleString();
};

export const AppSecurityRunList = ({
  runs,
  showTarget = true,
  emptyMessage = "No scans yet.",
}: AppSecurityRunListProps) => {
  if (runs.length === 0) {
    return (
      <p className="text-text-neutral-secondary text-sm">{emptyMessage}</p>
    );
  }

  return (
    <ul className={CARD_LIST_CLASS}>
      {runs.map((run) => {
        const scanId = run.attributes.scan_id || run.attributes.summary?.scan_id;
        const runHref = appSecurityHref(run.attributes.target_id, "runs", run.id);
        const findingCount = run.attributes.summary?.finding_count;
        const when = formatRunTime(
          run.attributes.finished_at || run.attributes.inserted_at,
        );
        return (
          <li key={run.id} className="flex flex-col gap-1.5 px-4 py-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <Link
                href={runHref}
                className="text-text-neutral-primary min-w-0 rounded-sm font-medium break-words underline-offset-2 hover:underline"
              >
                {showTarget
                  ? run.attributes.target_name || run.attributes.target_id
                  : `Scan ${when || run.id}`}
              </Link>
              <RunStatusBadge status={run.attributes.status} />
            </div>
            <p className="text-text-neutral-secondary text-sm">
              {[
                labelForTrivyMode(
                  run.attributes.target_mode || run.attributes.summary?.mode || "",
                ),
                run.attributes.trigger,
                typeof findingCount === "number"
                  ? `${findingCount} findings`
                  : "",
                showTarget ? when : "",
              ]
                .filter(Boolean)
                .join(" · ")}
            </p>
            {run.attributes.error ? (
              <p className="text-text-error-primary line-clamp-2 text-xs break-all">
                {run.attributes.error}
              </p>
            ) : null}
            {scanId ? (
              <Link
                href={findingsHrefForScan(scanId)}
                className="text-button-tertiary w-fit rounded-sm text-xs underline-offset-2 hover:underline"
              >
                Open findings
              </Link>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
};
