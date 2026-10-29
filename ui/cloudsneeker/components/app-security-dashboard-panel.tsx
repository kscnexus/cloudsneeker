import {
  type AppSecurityCategory,
  appSecurityCategoryHref,
  type AppSecurityDashboard,
} from "@/cloudsneeker/lib/app-security-dashboard";
import { formatReportDate } from "@/cloudsneeker/lib/report-view";
import { TRIVY_RUN_STATUS } from "@/cloudsneeker/types/trivy";

import { runStatusLabel } from "./run-status-badge";
import { SectionCard } from "./section-card";
import {
  SeverityBreakdown,
  type SeverityBreakdownItem,
} from "./severity-breakdown";
import { STAT_TILE_TONE, StatTile, type StatTileTone } from "./stat-tile";

interface AppSecurityDashboardPanelProps {
  dashboard: AppSecurityDashboard;
  /** Open findings by severity in each target's latest scan; `null` if unknown. */
  severityTotals: SeverityBreakdownItem[] | null;
  /** Category currently filtering the target list. */
  activeCategory: AppSecurityCategory | null;
}

const lastRunTone = (status: string | undefined): StatTileTone => {
  switch (status) {
    case TRIVY_RUN_STATUS.COMPLETED:
      return STAT_TILE_TONE.SUCCESS;
    case TRIVY_RUN_STATUS.FAILED:
      return STAT_TILE_TONE.DANGER;
    case TRIVY_RUN_STATUS.RUNNING:
    case TRIVY_RUN_STATUS.PENDING:
      return STAT_TILE_TONE.ACCENT;
    default:
      return STAT_TILE_TONE.NEUTRAL;
  }
};

export const AppSecurityDashboardPanel = ({
  dashboard,
  severityTotals,
  activeCategory,
}: AppSecurityDashboardPanelProps) => {
  const openTotal = severityTotals
    ? severityTotals.reduce((sum, item) => sum + item.count, 0)
    : dashboard.latestFindingCount;
  const critical =
    severityTotals?.find((item) => item.severity === "critical")?.count ?? null;
  const { lastRun } = dashboard;

  return (
    <div className="flex flex-col gap-6">
      <ul
        aria-label="Key figures"
        className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4"
      >
        <li className="min-w-0">
          <StatTile
            label="Targets"
            value={dashboard.targetCount}
            hint={`${dashboard.scheduledTargetCount} on a schedule`}
            tone={STAT_TILE_TONE.ACCENT}
          />
        </li>
        <li className="min-w-0">
          <StatTile
            label="Scans"
            value={dashboard.runCount}
            hint={[
              `${dashboard.activeRunCount} in progress`,
              dashboard.failedRunCount > 0
                ? `${dashboard.failedRunCount} failed recently`
                : "",
            ]
              .filter(Boolean)
              .join(" · ")}
          />
        </li>
        <li className="min-w-0">
          <StatTile
            label="Open findings"
            value={openTotal === null ? "—" : openTotal.toLocaleString("en-US")}
            hint={
              critical !== null && critical > 0
                ? `${critical} critical in the latest scans`
                : "From each target's latest scan"
            }
            tone={
              critical !== null && critical > 0
                ? STAT_TILE_TONE.CRITICAL
                : STAT_TILE_TONE.NEUTRAL
            }
          />
        </li>
        <li className="min-w-0">
          <StatTile
            label="Last scan"
            value={lastRun ? runStatusLabel(lastRun.status) : "—"}
            hint={
              lastRun
                ? `${lastRun.targetName}${lastRun.insertedAt ? ` · ${formatReportDate(lastRun.insertedAt)}` : ""}`
                : "No scans yet"
            }
            href={lastRun?.href}
            tone={lastRunTone(lastRun?.status)}
          />
        </li>
      </ul>

      {severityTotals && (openTotal ?? 0) > 0 ? (
        <SectionCard
          title="Open findings by severity"
          description="Failed, unmuted results from each target's latest completed scan."
        >
          <SeverityBreakdown items={severityTotals} />
        </SectionCard>
      ) : null}

      <SectionCard
        title="Coverage by area"
        description="Pick an area to filter the targets below; pick it again to clear the filter."
      >
        <ul
          aria-label="Areas"
          className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4"
        >
          {dashboard.categories.map((category) => {
            const selected = activeCategory === category.id;
            return (
              <li key={category.id} className="min-w-0">
                <StatTile
                  label={category.label}
                  value={category.targetCount}
                  hint={
                    category.targetCount === 0
                      ? category.description
                      : category.findingCount === null
                        ? `${category.targetCount === 1 ? "Target" : "Targets"} not scanned yet`
                        : `${category.findingCount} findings in the latest scans`
                  }
                  href={selected ? appSecurityCategoryHref(null) : category.href}
                  selected={selected}
                  tone={
                    selected
                      ? STAT_TILE_TONE.ACCENT
                      : category.targetCount > 0
                        ? STAT_TILE_TONE.INFO
                        : STAT_TILE_TONE.NEUTRAL
                  }
                />
              </li>
            );
          })}
        </ul>
      </SectionCard>
    </div>
  );
};
