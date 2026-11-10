import { Boxes, Cloud, Scale } from "lucide-react";
import Link from "next/link";

import { RunStatusBadge } from "@/cloudsneeker/components/run-status-badge";
import {
  ACTIVITY_KIND,
  ACTIVITY_KIND_LABEL,
  type ActivityItem,
  type ActivityKind,
} from "@/cloudsneeker/lib/dashboards";
import { formatReportDate } from "@/cloudsneeker/lib/report-view";
import { FOCUS_RING_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { cn } from "@/lib/utils";

const KIND_ICON: Record<ActivityKind, typeof Cloud> = {
  [ACTIVITY_KIND.CLOUD_SCAN]: Cloud,
  [ACTIVITY_KIND.APP_SCAN]: Boxes,
  [ACTIVITY_KIND.POLICY_RUN]: Scale,
};

const COUNT_NOUN: Record<ActivityKind, string> = {
  [ACTIVITY_KIND.CLOUD_SCAN]: "findings",
  [ACTIVITY_KIND.APP_SCAN]: "findings",
  [ACTIVITY_KIND.POLICY_RUN]: "resources matched",
};

interface ActivityListProps {
  items: ActivityItem[];
  emptyMessage: string;
}

/** Newest scans and dry-runs; each row opens the run or its findings. */
export const ActivityList = ({ items, emptyMessage }: ActivityListProps) => {
  if (items.length === 0) {
    return (
      <p className="text-text-neutral-tertiary py-2 text-sm">{emptyMessage}</p>
    );
  }
  return (
    <ul className="divide-border-neutral-secondary flex flex-col divide-y">
      {items.map((item) => {
        const Icon = KIND_ICON[item.kind];
        return (
          <li key={item.id}>
            <Link
              href={item.href}
              className={cn(
                "hover:bg-bg-neutral-tertiary/60 -mx-2 flex items-center gap-3 rounded-lg px-2 py-2.5 transition-colors",
                FOCUS_RING_CLASS,
              )}
            >
              <span
                aria-hidden="true"
                className="bg-bg-neutral-tertiary text-text-neutral-secondary flex size-8 shrink-0 items-center justify-center rounded-lg"
              >
                <Icon className="size-4" />
              </span>
              <span className="flex min-w-0 flex-1 flex-col">
                <span className="text-text-neutral-primary truncate text-sm font-medium">
                  {item.title}
                </span>
                <span className="text-text-neutral-tertiary truncate text-xs">
                  {ACTIVITY_KIND_LABEL[item.kind]} · {formatReportDate(item.at)}
                  {item.count !== null
                    ? ` · ${item.count.toLocaleString("en-US")} ${COUNT_NOUN[item.kind]}`
                    : ""}
                </span>
              </span>
              <RunStatusBadge status={item.state} />
            </Link>
          </li>
        );
      })}
    </ul>
  );
};
