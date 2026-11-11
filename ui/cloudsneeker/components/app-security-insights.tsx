import { Container, FileCode2, ShieldAlert } from "lucide-react";
import Link from "next/link";

import { ActivityList } from "@/cloudsneeker/components/dashboard/activity-list";
import {
  BAR_TONE,
  BarList,
  type BarListItem,
} from "@/cloudsneeker/components/dashboard/bar-list";
import { TrendColumns } from "@/cloudsneeker/components/dashboard/trend-columns";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import type { SeverityBreakdownItem } from "@/cloudsneeker/components/severity-breakdown";
import { STAT_TILE_TONE, StatTile } from "@/cloudsneeker/components/stat-tile";
import {
  APP_SECURITY_CATEGORY,
  type AppSecurityCategory,
  type AppSecurityDashboard,
  appSecurityCategoryHref,
} from "@/cloudsneeker/lib/app-security-dashboard";
import {
  areaFindingsPageHref,
  areaTriagePageHref,
} from "@/cloudsneeker/lib/area-findings";
import {
  ACTIVITY_STATE,
  type ActivityItem,
  percentOf,
  type RankedTarget,
  REMEDIATION_STATUS_LABEL,
  type RemediationProgress,
  type TrendPoint,
} from "@/cloudsneeker/lib/dashboards";
import { formatReportDay } from "@/cloudsneeker/lib/report-view";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";
import {
  TRIVY_MODE,
  type TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";
import { Button } from "@/components/shadcn";
import { FINDING_TRIAGE_STATUS } from "@/types/findings-triage";

const AREA = FINDING_AREA.APPLICATION_SECURITY;
const RISKY_TARGET_LIMIT = 6;
const FAILED_SCAN_LIMIT = 5;

/** Categories shown under Code security (SCA, SAST, secrets, IaC, SBOM). */
const CODE_CATEGORIES: readonly AppSecurityCategory[] = [
  APP_SECURITY_CATEGORY.DEPENDENCIES,
  APP_SECURITY_CATEGORY.CODE,
  APP_SECURITY_CATEGORY.SECRETS,
  APP_SECURITY_CATEGORY.IAC,
  APP_SECURITY_CATEGORY.SBOM,
];

const CODE_MODES = new Set<string>([
  TRIVY_MODE.REPO,
  TRIVY_MODE.FS,
  TRIVY_MODE.SAST,
  TRIVY_MODE.IAC,
]);

const formatCount = (value: number | null | undefined): string =>
  value === null || value === undefined ? "—" : value.toLocaleString("en-US");

const imageCount = (target: TrivyTargetResource): number => {
  const { images, image } = target.attributes.config ?? {};
  if (Array.isArray(images) && images.length > 0) return images.length;
  return image ? 1 : 0;
};

const targetBars = (targets: RankedTarget[], limit: number): BarListItem[] => {
  const max = Math.max(1, ...targets.map((target) => target.findings));
  return targets.slice(0, limit).map((target) => ({
    id: target.targetId,
    label: target.name,
    value: formatCount(target.findings),
    percent: (target.findings / max) * 100,
    tone: target.findings > 0 ? BAR_TONE.FAIL : BAR_TONE.PASS,
    hint: [
      labelForTrivyMode(target.mode),
      target.at ? formatReportDay(target.at) : "",
    ]
      .filter(Boolean)
      .join(" · "),
    href: appSecurityHref(target.targetId),
  }));
};

export interface AppSecurityInsightsProps {
  dashboard: AppSecurityDashboard;
  targets: TrivyTargetResource[];
  /** Targets ranked by findings in their latest completed scan. */
  rankedTargets: RankedTarget[];
  severityTotals: SeverityBreakdownItem[] | null;
  /** Open findings in the area (fix available + no fix), or null. */
  openTotal: number | null;
  remediation: RemediationProgress | null;
  trend: TrendPoint[];
  /** Recent scans; the failed ones are listed. */
  failedScans: ActivityItem[];
}

/**
 * Application Security dashboard sections below the posture panel:
 * vulnerability management, container and code security, application risk
 * and failed scans. Every figure comes from the hub's own requests.
 */
export const AppSecurityInsights = ({
  dashboard,
  targets,
  rankedTargets,
  severityTotals,
  openTotal,
  remediation,
  trend,
  failedScans,
}: AppSecurityInsightsProps) => {
  const severity = (name: string) =>
    severityTotals?.find((item) => item.severity === name);
  const critical = severity("critical");
  const high = severity("high");
  const failed = failedScans
    .filter((item) => item.state === ACTIVITY_STATE.FAILED)
    .slice(0, FAILED_SCAN_LIMIT);
  const withIssues = rankedTargets.filter((target) => target.findings > 0);

  const imageTargets = targets.filter(
    (target) => target.attributes.mode === TRIVY_MODE.IMAGE,
  );
  const imageTargetIds = new Set(imageTargets.map((target) => target.id));
  const rankedImages = rankedTargets.filter((target) =>
    imageTargetIds.has(target.targetId),
  );
  const containerSummary = dashboard.categories.find(
    (category) => category.id === APP_SECURITY_CATEGORY.CONTAINERS,
  );

  const codeCategories = dashboard.categories.filter((category) =>
    CODE_CATEGORIES.includes(category.id),
  );
  const codeMax = Math.max(
    1,
    ...codeCategories.map((category) => category.findingCount ?? 0),
  );
  const rankedRepositories = rankedTargets.filter((target) =>
    CODE_MODES.has(target.mode),
  );

  const remediationBars: BarListItem[] = remediation
    ? remediation.counts.map((row) => ({
        id: row.status,
        label: REMEDIATION_STATUS_LABEL[row.status],
        value: formatCount(row.count),
        percent: percentOf(row.count, remediation.total) ?? 0,
        tone:
          row.status === FINDING_TRIAGE_STATUS.OPEN
            ? BAR_TONE.FAIL
            : row.status === FINDING_TRIAGE_STATUS.RESOLVED
              ? BAR_TONE.PASS
              : row.status === FINDING_TRIAGE_STATUS.REMEDIATING
                ? BAR_TONE.ACCENT
                : BAR_TONE.NEUTRAL,
        href: areaTriagePageHref(AREA, row.status),
      }))
    : [];

  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        title="Vulnerability management"
        description="Open findings from the latest scan of every target, and where they stand in triage."
      >
        <ul
          aria-label="Vulnerability figures"
          className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4"
        >
          <li className="min-w-0">
            <StatTile
              label="Open findings"
              value={formatCount(openTotal)}
              icon={<ShieldAlert />}
              href={areaFindingsPageHref(AREA, {})}
            />
          </li>
          <li className="min-w-0">
            <StatTile
              label="Critical"
              tone={STAT_TILE_TONE.CRITICAL}
              value={formatCount(critical?.count ?? null)}
              href={critical?.href}
            />
          </li>
          <li className="min-w-0">
            <StatTile
              label="High"
              tone={STAT_TILE_TONE.HIGH}
              value={formatCount(high?.count ?? null)}
              href={high?.href}
            />
          </li>
          <li className="min-w-0">
            <StatTile
              label="Targets with findings"
              tone={
                withIssues.length > 0
                  ? STAT_TILE_TONE.WARNING
                  : STAT_TILE_TONE.SUCCESS
              }
              value={`${withIssues.length} / ${dashboard.targetCount}`}
              hint="From each target's latest completed scan"
            />
          </li>
        </ul>
        <div className="flex min-w-0 flex-col gap-2">
          <h3 className="text-text-neutral-primary flex items-baseline justify-between gap-3 text-sm font-semibold">
            Remediation progress
            {remediation?.handledPercent !== null &&
            remediation?.handledPercent !== undefined ? (
              <span className="text-text-neutral-secondary text-xs font-normal">
                {remediation.handledPercent}% triaged
              </span>
            ) : null}
          </h3>
          {remediation ? (
            <BarList
              label="Open findings by triage status"
              items={remediationBars}
              emptyMessage="No open findings."
              className="sm:grid sm:grid-cols-2 sm:gap-x-6 lg:grid-cols-3"
            />
          ) : (
            <p className="text-text-neutral-tertiary text-sm">
              Triage status could not be loaded. Reload the page in a moment.
            </p>
          )}
        </div>
      </SectionCard>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard
          title="Container security"
          description="Image targets and the findings in their latest scan."
          actions={
            <Button asChild variant="ghost" size="sm">
              <Link
                href={appSecurityCategoryHref(APP_SECURITY_CATEGORY.CONTAINERS)}
              >
                All image targets
              </Link>
            </Button>
          }
        >
          <ul
            aria-label="Container figures"
            className="grid grid-cols-1 gap-3 sm:grid-cols-3"
          >
            <li className="min-w-0">
              <StatTile
                label="Images scanned"
                icon={<Container />}
                value={formatCount(
                  imageTargets.reduce(
                    (sum, target) => sum + imageCount(target),
                    0,
                  ),
                )}
                hint={`${imageTargets.length} image target${imageTargets.length === 1 ? "" : "s"}`}
              />
            </li>
            <li className="min-w-0">
              <StatTile
                label="Targets with findings"
                tone={
                  rankedImages.some((target) => target.findings > 0)
                    ? STAT_TILE_TONE.WARNING
                    : STAT_TILE_TONE.SUCCESS
                }
                value={`${rankedImages.filter((target) => target.findings > 0).length} / ${imageTargets.length}`}
              />
            </li>
            <li className="min-w-0">
              <StatTile
                label="Findings in images"
                tone={STAT_TILE_TONE.DANGER}
                value={formatCount(containerSummary?.findingCount ?? null)}
                href={containerSummary?.href}
              />
            </li>
          </ul>
          <BarList
            label="Image targets by findings"
            items={targetBars(rankedImages, RISKY_TARGET_LIMIT)}
            emptyMessage={
              imageTargets.length === 0
                ? "No image targets yet. Create one to scan container images."
                : "No completed image scans yet."
            }
          />
        </SectionCard>

        <SectionCard
          title="Code security"
          description="Dependencies (SCA), source code (SAST), secrets, Infrastructure as Code and SBOMs."
        >
          <BarList
            label="Findings by scan type"
            items={codeCategories.map((category) => ({
              id: category.id,
              label: category.label,
              value: formatCount(category.findingCount),
              percent: ((category.findingCount ?? 0) / codeMax) * 100,
              tone:
                (category.findingCount ?? 0) > 0
                  ? BAR_TONE.FAIL
                  : BAR_TONE.NEUTRAL,
              hint: `${category.targetCount} target${category.targetCount === 1 ? "" : "s"}`,
              href: category.href,
            }))}
            emptyMessage="No code targets yet."
          />
          <div className="flex min-w-0 flex-col gap-2">
            <h3 className="text-text-neutral-primary flex items-center gap-2 text-sm font-semibold">
              <FileCode2 aria-hidden="true" className="size-4" />
              Findings by repository
            </h3>
            <BarList
              label="Repositories by findings"
              items={targetBars(rankedRepositories, RISKY_TARGET_LIMIT)}
              emptyMessage="No completed repository or code scans yet."
            />
          </div>
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard
          title="Application risk"
          description="Targets with the most findings in their latest completed scan."
        >
          <BarList
            label="Riskiest targets"
            items={targetBars(rankedTargets, RISKY_TARGET_LIMIT)}
            emptyMessage="No completed scans yet."
          />
        </SectionCard>
        <SectionCard
          title="Findings reported over time"
          description="Findings reported by completed scans per day, last 30 days."
        >
          <TrendColumns
            points={trend}
            noun="findings reported"
            emptyMessage="No completed scans in the last 30 days."
          />
        </SectionCard>
      </div>

      {failed.length > 0 ? (
        <SectionCard
          title="Failed scans"
          description="Open a scan to see why it failed and run it again."
        >
          <ActivityList items={failed} emptyMessage="No failed scans." />
        </SectionCard>
      ) : null}
    </div>
  );
};
