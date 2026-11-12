import Link from "next/link";

import { StandardSeverityBadge } from "@/cloudsneeker/components/standard/standard-severity-badge";
import { areaFindingsPageHref } from "@/cloudsneeker/lib/area-findings";
import { CARD_LIST_CLASS } from "@/cloudsneeker/lib/ui-classes";
import {
  AREA_FIX_FILTER,
  type AreaFindingAttributes,
  FINDING_AREA,
} from "@/cloudsneeker/types/area-findings";
import { Button } from "@/components/shadcn";

import { AreaFindingFixCell } from "./area-finding-fix";
import { SectionCard } from "./section-card";
import { STAT_TILE_TONE, StatTile } from "./stat-tile";

interface AppSecurityFixesCardProps {
  /** Open findings with a fix, or `null` when the count failed. */
  fixable: number | null;
  /** Open findings without a fix yet, or `null` when the count failed. */
  unfixable: number | null;
  /** The most severe fixable findings, most severe first. */
  topFixes: AreaFindingAttributes[];
}

const AREA = FINDING_AREA.APPLICATION_SECURITY;

const count = (value: number | null): string =>
  value === null ? "—" : value.toLocaleString();

/** Dashboard card: how many findings can be fixed now, and the top fixes. */
export const AppSecurityFixesCard = ({
  fixable,
  unfixable,
  topFixes,
}: AppSecurityFixesCardProps) => {
  const total = (fixable ?? 0) + (unfixable ?? 0);
  const share =
    fixable !== null && total > 0
      ? `${Math.round((fixable / total) * 100)}% of open findings`
      : "Upgrade, patch or rotate";
  return (
    <SectionCard
      title="Fixes"
      description="Findings with a known fix: a fixed package version, a resolution or a code change."
      actions={
        <Button asChild size="sm" variant="outline">
          <Link
            href={areaFindingsPageHref(AREA, {
              fix: AREA_FIX_FILTER.AVAILABLE,
            })}
          >
            View fixable findings
          </Link>
        </Button>
      }
    >
      <div className="flex flex-col gap-4">
        <ul
          aria-label="Fix status"
          className="grid grid-cols-1 gap-3 sm:grid-cols-2"
        >
          <li className="min-w-0">
            <StatTile
              label="Fix available"
              value={count(fixable)}
              hint={share}
              tone={STAT_TILE_TONE.SUCCESS}
              href={areaFindingsPageHref(AREA, {
                fix: AREA_FIX_FILTER.AVAILABLE,
              })}
            />
          </li>
          <li className="min-w-0">
            <StatTile
              label="No fix yet"
              value={count(unfixable)}
              hint="Mitigate, accept the risk or replace"
              tone={STAT_TILE_TONE.WARNING}
              href={areaFindingsPageHref(AREA, {
                fix: AREA_FIX_FILTER.UNAVAILABLE,
              })}
            />
          </li>
        </ul>
        {topFixes.length > 0 ? (
          <div className="flex flex-col gap-2">
            <h3 className="text-text-neutral-primary text-sm font-semibold">
              Top fixes
            </h3>
            <ul aria-label="Top fixes" className={CARD_LIST_CLASS}>
              {topFixes.map((finding) => (
                <li
                  key={finding.uid}
                  className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
                >
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <Link
                      href={areaFindingsPageHref(AREA, { search: finding.uid })}
                      className="text-text-neutral-primary truncate text-sm font-medium underline-offset-2 hover:underline"
                    >
                      {finding.title}
                    </Link>
                    <p className="text-text-neutral-tertiary truncate text-xs">
                      {[finding.check_id, finding.location, finding.source_name]
                        .filter(Boolean)
                        .join(" · ")}
                    </p>
                    {finding.fix_summary ? (
                      <p className="text-text-neutral-secondary line-clamp-2 text-xs">
                        {finding.fix_summary}
                      </p>
                    ) : null}
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <StandardSeverityBadge severity={finding.severity} />
                    <AreaFindingFixCell finding={finding} />
                  </div>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </div>
    </SectionCard>
  );
};
