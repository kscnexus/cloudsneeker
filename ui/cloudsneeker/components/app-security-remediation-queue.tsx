import Link from "next/link";

import { listAreaFindings } from "@/cloudsneeker/actions/finding-triage";
import {
  RISK_PRIORITY_INFO,
  RISK_PRIORITY_RULES,
} from "@/cloudsneeker/lib/app-security-priority";
import { areaFindingsPageHref } from "@/cloudsneeker/lib/area-findings";
import { isListResponse } from "@/cloudsneeker/lib/findings-links";
import {
  type AreaFindingsResponse,
  FINDING_AREA,
  RISK_PRIORITY,
  type RiskPriority,
} from "@/cloudsneeker/types/area-findings";

import { SectionCard } from "./section-card";

const AREA = FINDING_AREA.APPLICATION_SECURITY;

interface QueueTile {
  label: string;
  value: number;
  href: string;
  hint: string;
}

const priorityTile = (
  priority: RiskPriority,
  counts: Partial<Record<RiskPriority, number>> | undefined,
): QueueTile => {
  const info = RISK_PRIORITY_INFO[priority];
  return {
    label: `${info.code} ${info.label}`,
    value: counts?.[priority] ?? 0,
    href: areaFindingsPageHref(AREA, { priority }),
    hint: `Fix within ${info.slaDays} days`,
  };
};

/** Findings that need action: overdue first, then P0 to P2, then fixes in progress. */
export const AppSecurityRemediationQueue = async () => {
  const [response, remediating] = await Promise.all([
    // No triage filter: the counts must match the findings page each tile
    // opens. Overdue already leaves out resolved and accepted findings.
    listAreaFindings({ "filter[area]": AREA, "page[size]": "1" }),
    listAreaFindings({
      "filter[area]": AREA,
      "filter[triage_status__in]": "remediating",
      "page[size]": "1",
    }),
  ]);
  if (!isListResponse(response)) return null;
  const meta = (response as AreaFindingsResponse).meta;
  const tiles: QueueTile[] = [
    {
      label: "Overdue",
      value: meta?.overdue_count ?? 0,
      href: areaFindingsPageHref(AREA, { overdue: true }),
      hint: "Past the due date",
    },
    priorityTile(RISK_PRIORITY.P0, meta?.priority_counts),
    priorityTile(RISK_PRIORITY.P1, meta?.priority_counts),
    priorityTile(RISK_PRIORITY.P2, meta?.priority_counts),
    {
      label: "Remediating",
      value: isListResponse(remediating)
        ? ((remediating as AreaFindingsResponse).meta?.pagination?.count ?? 0)
        : 0,
      href: areaFindingsPageHref(AREA, { triage: "remediating" }),
      hint: "Fix in progress",
    },
  ];

  return (
    <SectionCard
      title="Remediation queue"
      description={`Current findings by risk priority. ${RISK_PRIORITY_RULES} Mark a finding resolved only after a rescan no longer reports it.`}
      contentClassName="p-4 sm:p-5"
    >
      <nav
        aria-label="Remediation queue"
        className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5"
      >
        {tiles.map((tile) => (
          <Link
            key={tile.label}
            href={tile.href}
            className="border-border-neutral-secondary hover:border-border-neutral-primary flex flex-col gap-0.5 rounded-lg border px-3 py-2 transition-colors"
          >
            <span className="text-text-neutral-secondary text-xs font-medium">
              {tile.label}
            </span>
            <span className="text-text-neutral-primary text-xl font-semibold tabular-nums">
              {tile.value}
            </span>
            <span className="text-text-neutral-tertiary text-[11px]">
              {tile.hint}
            </span>
          </Link>
        ))}
      </nav>
    </SectionCard>
  );
};
