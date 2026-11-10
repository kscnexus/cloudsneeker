import { ChevronRight } from "lucide-react";
import Link from "next/link";

import {
  type RunGroup,
  SCANS_PER_TARGET,
} from "@/cloudsneeker/lib/app-security-scan-history";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { FOCUS_RING_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import { Button } from "@/components/shadcn";
import { cn } from "@/lib/utils";

import { AppSecurityRunList } from "./app-security-run-list";
import { RunStatusBadge } from "./run-status-badge";

interface AppSecurityRunGroupsProps {
  groups: RunGroup[];
  emptyMessage?: string;
}

const scanCount = (count: number) =>
  count >= SCANS_PER_TARGET
    ? `Latest ${SCANS_PER_TARGET} scans`
    : `${count} ${count === 1 ? "scan" : "scans"}`;

const formatDate = (value: string | undefined) => {
  const date = new Date(value ?? "");
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleString();
};

/** Scan history grouped per target; the most recently scanned one starts open. */
export const AppSecurityRunGroups = ({
  groups,
  emptyMessage = "No scans yet.",
}: AppSecurityRunGroupsProps) => {
  if (groups.length === 0) {
    return (
      <p className="text-text-neutral-secondary text-sm">{emptyMessage}</p>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      {groups.map((group, index) => {
        const latest = group.runs[0];
        return (
          <details
            key={group.targetId}
            open={index === 0}
            className="group border-border-neutral-secondary rounded-lg border"
          >
            <summary
              className={cn(
                "flex cursor-pointer list-none flex-wrap items-center gap-x-3 gap-y-1 rounded-lg px-4 py-3 [&::-webkit-details-marker]:hidden",
                FOCUS_RING_CLASS,
              )}
            >
              <ChevronRight
                aria-hidden="true"
                className="text-text-neutral-tertiary size-4 shrink-0 transition-transform group-open:rotate-90"
              />
              <span className="text-text-neutral-primary min-w-0 font-medium break-words">
                {group.targetName}
              </span>
              <span className="text-text-neutral-secondary text-sm">
                {[
                  labelForTrivyMode(group.targetMode),
                  scanCount(group.runs.length),
                  formatDate(latest?.attributes.inserted_at),
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </span>
              {latest ? (
                <span className="ml-auto">
                  <RunStatusBadge status={latest.attributes.status} />
                </span>
              ) : null}
            </summary>
            <div className="flex flex-col gap-3 px-4 pb-4">
              <AppSecurityRunList runs={group.runs} showTarget={false} />
              <div>
                <Button asChild variant="ghost" size="sm">
                  <Link href={appSecurityHref(group.targetId)}>
                    Open target
                  </Link>
                </Button>
              </div>
            </div>
          </details>
        );
      })}
    </div>
  );
};
