import Link from "next/link";

import {
  TRIAGE_STATUS_FILTERS,
  triagePageHref,
  triageStatusLabel,
} from "@/cloudsneeker/lib/finding-triage";
import { cn } from "@/lib/utils";
import type { FindingTriageStatus } from "@/types/findings-triage";

interface FindingTriageStatusFilterProps {
  active: FindingTriageStatus | null;
}

const OPTIONS: { status: FindingTriageStatus | null; label: string }[] = [
  { status: null, label: "All" },
  ...TRIAGE_STATUS_FILTERS.map((status) => ({
    status,
    label: triageStatusLabel(status),
  })),
];

/** "Triage status" filter: one link per status, server rendered. */
export const FindingTriageStatusFilter = ({
  active,
}: FindingTriageStatusFilterProps) => (
  <nav aria-label="Triage status" className="flex flex-wrap gap-2">
    {OPTIONS.map(({ status, label }) => {
      const isActive = status === active;
      return (
        <Link
          key={label}
          href={triagePageHref(status)}
          aria-current={isActive ? "page" : undefined}
          className={cn(
            "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
            isActive
              ? "border-button-primary bg-button-primary text-black"
              : "border-border-neutral-secondary text-text-neutral-secondary hover:text-text-neutral-primary",
          )}
        >
          {label}
        </Link>
      );
    })}
  </nav>
);
