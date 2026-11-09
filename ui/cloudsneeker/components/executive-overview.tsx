import {
  ArrowRight,
  Boxes,
  Cloud,
  Scale,
  ShieldAlert,
  ShieldCheck,
  SquareChartGantt,
} from "lucide-react";
import Link from "next/link";
import { type ReactNode, Suspense } from "react";

import { OverviewBanner } from "@/app/(prowler)/_overview/_components/overview-banner";
import { OVERVIEW_BANNER_VARIANT } from "@/app/(prowler)/_overview/_lib/overview-banner";
import { ActivityList } from "@/cloudsneeker/components/dashboard/activity-list";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { RiskOverview } from "@/cloudsneeker/components/risk-overview";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { SeverityBreakdown } from "@/cloudsneeker/components/severity-breakdown";
import { STAT_TILE_TONE, StatTile } from "@/cloudsneeker/components/stat-tile";
import {
  areaFindingHref,
  areaFindingsPageHref,
} from "@/cloudsneeker/lib/area-findings";
import {
  appScanActivity,
  cloudScanActivity,
  countAreaFindings,
  loadAppRuns,
  loadAppTargets,
  loadCloudScans,
  loadCloudSeverity,
  loadComplianceFrameworks,
  loadCriticalFindings,
  loadPolicyRuns,
  loadProviderCounts,
  policyRunActivity,
} from "@/cloudsneeker/lib/dashboard-data";
import {
  ACTIVITY_STATE,
  mergeActivity,
  summarizeCompliance,
} from "@/cloudsneeker/lib/dashboards";
import { FOCUS_RING_CLASS } from "@/cloudsneeker/lib/ui-classes";
import {
  appSecurityHref,
  governanceHref,
  PRODUCT_ROUTE,
} from "@/cloudsneeker/routes";
import {
  type AreaFindingResource,
  FINDING_AREA,
  type FindingArea,
} from "@/cloudsneeker/types/area-findings";
import {
  APP_SIDEBAR_MODE,
  AppSidebarModeSync,
} from "@/components/layout/app-sidebar";
import { Badge, Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";
import { cn } from "@/lib/utils";

const ACTIVITY_LIMIT = 8;
const CRITICAL_PER_AREA = 4;

const AREA_LABEL: Record<FindingArea, string> = {
  cloud: "Cloud",
  application_security: "Application",
  governance: "Governance",
};

const formatCount = (value: number | null | undefined): string =>
  value === null || value === undefined ? "—" : value.toLocaleString("en-US");

const scoreTone = (score: number | null) =>
  score === null
    ? STAT_TILE_TONE.NEUTRAL
    : score >= 80
      ? STAT_TILE_TONE.SUCCESS
      : score >= 50
        ? STAT_TILE_TONE.WARNING
        : STAT_TILE_TONE.DANGER;

/** A product area summary with a few figures and a link to its dashboard. */
const AreaSummaryCard = ({
  title,
  description,
  icon,
  href,
  linkLabel,
  children,
}: {
  title: string;
  description: string;
  icon: ReactNode;
  href: string;
  linkLabel: string;
  children: ReactNode;
}) => (
  <SectionCard
    title={title}
    description={description}
    actions={
      <Button asChild variant="ghost" size="sm">
        <Link href={href}>
          {linkLabel}
          <ArrowRight aria-hidden="true" />
        </Link>
      </Button>
    }
    className="h-full"
  >
    <div className="flex items-start gap-3">
      <span
        aria-hidden="true"
        className="bg-bg-neutral-tertiary text-text-neutral-secondary flex size-9 shrink-0 items-center justify-center rounded-lg [&>svg]:size-4"
      >
        {icon}
      </span>
      <dl className="grid min-w-0 flex-1 grid-cols-2 gap-x-4 gap-y-3">
        {children}
      </dl>
    </div>
  </SectionCard>
);

const Figure = ({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "danger" | "success";
}) => (
  <div className="flex min-w-0 flex-col gap-0.5">
    <dt className="text-text-neutral-secondary truncate text-xs">{label}</dt>
    <dd
      className={cn(
        "text-lg font-semibold tabular-nums",
        tone === "danger"
          ? "text-text-error-primary"
          : tone === "success"
            ? "text-text-success-primary"
            : "text-text-neutral-primary",
      )}
    >
      {value}
    </dd>
  </div>
);

const CriticalList = ({ findings }: { findings: AreaFindingResource[] }) => {
  if (findings.length === 0) {
    return (
      <p className="text-text-neutral-tertiary py-2 text-sm">
        No open critical findings. Nice.
      </p>
    );
  }
  return (
    <ul className="divide-border-neutral-secondary flex flex-col divide-y">
      {findings.map((finding) => {
        const { attributes } = finding;
        return (
          <li key={`${attributes.area}-${finding.id}`}>
            <Link
              href={areaFindingHref(attributes.area, {
                uid: attributes.uid,
                checkId: attributes.check_id,
              })}
              className={cn(
                "hover:bg-bg-neutral-tertiary/60 -mx-2 flex items-center gap-3 rounded-lg px-2 py-2.5 transition-colors",
                FOCUS_RING_CLASS,
              )}
            >
              <span
                aria-hidden="true"
                className="bg-bg-data-critical h-8 w-1 shrink-0 rounded-full"
              />
              <span className="flex min-w-0 flex-1 flex-col">
                <span className="text-text-neutral-primary truncate text-sm font-medium">
                  {attributes.title || attributes.check_id}
                </span>
                <span className="text-text-neutral-tertiary truncate text-xs">
                  {[
                    attributes.source_name,
                    attributes.resource_name || attributes.location,
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                </span>
              </span>
              <Badge variant="tag">{AREA_LABEL[attributes.area]}</Badge>
            </Link>
          </li>
        );
      })}
    </ul>
  );
};

const ExecutiveOverviewSSR = async () => {
  const [
    providerCounts,
    cloudSeverity,
    appOpen,
    appCritical,
    frameworks,
    appTargets,
    appRuns,
    policyRuns,
    cloudScans,
    cloudCritical,
    appCriticalFindings,
  ] = await Promise.all([
    loadProviderCounts(),
    loadCloudSeverity(),
    countAreaFindings(FINDING_AREA.APPLICATION_SECURITY),
    countAreaFindings(FINDING_AREA.APPLICATION_SECURITY, {
      "filter[severity__in]": "critical",
    }),
    loadComplianceFrameworks(),
    loadAppTargets(),
    loadAppRuns(),
    loadPolicyRuns(),
    loadCloudScans(ACTIVITY_LIMIT * 3),
    // Extra rows: code-repository sources are dropped below.
    loadCriticalFindings(FINDING_AREA.CLOUD, CRITICAL_PER_AREA * 3),
    loadCriticalFindings(FINDING_AREA.APPLICATION_SECURITY, CRITICAL_PER_AREA),
  ]);

  const compliance = frameworks ? summarizeCompliance(frameworks) : null;
  const cloudCriticalCount =
    cloudSeverity?.find((item) => item.severity === "critical") ?? null;
  const cloudOpen = cloudSeverity
    ? cloudSeverity.reduce((sum, item) => sum + item.count, 0)
    : null;
  const appFailedRuns = appRuns
    ? appRuns.filter((run) => run.attributes.status === ACTIVITY_STATE.FAILED)
        .length
    : null;
  const latestPolicyRuns = policyRuns ?? [];
  const policiesWithMatches = new Set(
    latestPolicyRuns
      .filter(
        (run) =>
          run.attributes.status === ACTIVITY_STATE.COMPLETED &&
          Number(run.attributes.summary?.resource_count ?? 0) > 0,
      )
      .map((run) => run.attributes.policy_id),
  ).size;

  // Application scans also create a scan record; list them once, as
  // application scans, and keep their sources out of the cloud lists.
  const appScanIds = new Set(
    (appRuns ?? [])
      .map((run) => run.attributes.scan_id || run.attributes.summary?.scan_id)
      .filter((id): id is string => Boolean(id)),
  );
  const appProviderIds = new Set(
    (appTargets ?? []).map((target) => target.attributes.provider_id),
  );
  const activity = mergeActivity(
    [
      cloudScans
        ? cloudScanActivity(
            cloudScans.filter((scan) => !appScanIds.has(scan.id)),
          )
        : [],
      appRuns ? appScanActivity(appRuns) : [],
      policyRuns ? policyRunActivity(policyRuns) : [],
    ],
    ACTIVITY_LIMIT,
  );
  const activityFailed = !cloudScans && !appRuns && !policyRuns;

  const critical = [
    ...(cloudCritical ?? [])
      .filter(
        (finding) =>
          !finding.attributes.provider_id ||
          !appProviderIds.has(finding.attributes.provider_id),
      )
      .slice(0, CRITICAL_PER_AREA),
    ...(appCriticalFindings ?? []),
  ];
  const criticalFailed = cloudCritical === null && appCriticalFindings === null;

  return (
    <div className="flex flex-col gap-6">
      <ul
        aria-label="Platform figures"
        className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4"
      >
        <li className="min-w-0">
          <StatTile
            label="Cloud accounts"
            icon={<Cloud />}
            value={formatCount(providerCounts?.total)}
            hint={
              providerCounts
                ? `${providerCounts.connected} connected`
                : "Could not be loaded"
            }
            href="/providers"
          />
        </li>
        <li className="min-w-0">
          <StatTile
            label="Critical cloud findings"
            icon={<ShieldAlert />}
            tone={STAT_TILE_TONE.CRITICAL}
            value={formatCount(cloudCriticalCount?.count)}
            hint={
              cloudOpen !== null
                ? `${formatCount(cloudOpen)} failed checks in total`
                : undefined
            }
            href={cloudCriticalCount?.href}
          />
        </li>
        <li className="min-w-0">
          <StatTile
            label="Open vulnerabilities"
            icon={<Boxes />}
            tone={STAT_TILE_TONE.HIGH}
            value={formatCount(appOpen)}
            hint={
              appCritical !== null
                ? `${formatCount(appCritical)} critical`
                : undefined
            }
            href={areaFindingsPageHref(FINDING_AREA.APPLICATION_SECURITY, {})}
          />
        </li>
        <li className="min-w-0">
          <StatTile
            label="Compliance score"
            icon={<ShieldCheck />}
            tone={scoreTone(compliance?.percent ?? null)}
            value={
              compliance?.percent === null || compliance?.percent === undefined
                ? "—"
                : `${compliance.percent}%`
            }
            hint={
              compliance
                ? `${compliance.frameworkCount} framework${compliance.frameworkCount === 1 ? "" : "s"}`
                : "Could not be loaded"
            }
            href={governanceHref()}
          />
        </li>
      </ul>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <AreaSummaryCard
          title="Cloud security"
          description="Failed checks in the latest scan of each account."
          icon={<Cloud />}
          href={PRODUCT_ROUTE.CLOUD_SECURITY}
          linkLabel="Dashboard"
        >
          {cloudSeverity ? (
            <div className="col-span-2">
              <SeverityBreakdown
                items={cloudSeverity}
                label="Failed cloud checks by severity"
                className="[&>ul]:grid-cols-2 sm:[&>ul]:grid-cols-3 xl:[&>ul]:grid-cols-2"
              />
            </div>
          ) : (
            <Figure label="Failed checks" value="—" />
          )}
        </AreaSummaryCard>
        <AreaSummaryCard
          title="Application security"
          description="Repositories, images, code and clusters."
          icon={<Boxes />}
          href={appSecurityHref()}
          linkLabel="Dashboard"
        >
          <Figure label="Targets" value={formatCount(appTargets?.length)} />
          <Figure label="Open findings" value={formatCount(appOpen)} />
          <Figure
            label="Critical"
            value={formatCount(appCritical)}
            tone={appCritical ? "danger" : undefined}
          />
          <Figure
            label="Failed scans"
            value={formatCount(appFailedRuns)}
            tone={appFailedRuns ? "danger" : undefined}
          />
        </AreaSummaryCard>
        <AreaSummaryCard
          title="Governance"
          description="Compliance frameworks and cloud policies."
          icon={<Scale />}
          href={governanceHref()}
          linkLabel="Dashboard"
        >
          <Figure
            label="Compliance"
            value={
              compliance?.percent === null || compliance?.percent === undefined
                ? "—"
                : `${compliance.percent}%`
            }
          />
          <Figure
            label="Failed controls"
            value={formatCount(compliance?.failed)}
            tone={compliance?.failed ? "danger" : undefined}
          />
          <Figure
            label="Frameworks"
            value={formatCount(compliance?.frameworkCount)}
          />
          <Figure
            label="Policies with matches"
            value={policyRuns ? formatCount(policiesWithMatches) : "—"}
          />
        </AreaSummaryCard>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard
          title="Needs attention"
          description="Open critical findings in cloud accounts and applications, most recently seen first."
        >
          {criticalFailed ? (
            <p className="text-text-neutral-tertiary text-sm">
              Critical findings could not be loaded.
            </p>
          ) : (
            <CriticalList findings={critical} />
          )}
        </SectionCard>
        <SectionCard
          title="Recent activity"
          description="Newest cloud scans, application scans and policy dry-runs."
          actions={
            <Button asChild variant="ghost" size="sm">
              <Link href="/scans">All scans</Link>
            </Button>
          }
        >
          {activityFailed ? (
            <p className="text-text-neutral-tertiary text-sm">
              Activity could not be loaded.
            </p>
          ) : (
            <ActivityList
              items={activity}
              emptyMessage="No scans yet. Launch a scan to get started."
            />
          )}
        </SectionCard>
      </div>
    </div>
  );
};

const ExecutiveOverviewSkeleton = () => (
  <div className="flex flex-col gap-6">
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {Array.from({ length: 4 }, (_, index) => (
        <Skeleton key={index} className="h-24 rounded-xl" />
      ))}
    </div>
    <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
      {Array.from({ length: 3 }, (_, index) => (
        <Skeleton key={index} className="h-48 rounded-xl" />
      ))}
    </div>
    <Skeleton className="h-72 rounded-xl" />
  </div>
);

/**
 * Executive Overview: one summary of the whole platform, with links to the
 * Cloud Security, Application Security and Governance dashboards for detail.
 * Rendered by the upstream Overview page through one `cloudsneeker-hook`.
 */
export const ExecutiveOverview = () => (
  <ContentLayout title="Overview" icon={<SquareChartGantt />}>
    <AppSidebarModeSync mode={APP_SIDEBAR_MODE.BROWSE} />
    <PageHeader description="Security posture across cloud accounts, applications and governance. Open an area's dashboard for the detail." />
    <RiskOverview />
    <Suspense fallback={<ExecutiveOverviewSkeleton />}>
      <ExecutiveOverviewSSR />
    </Suspense>
    <div className="mt-6">
      <OverviewBanner
        variant={OVERVIEW_BANNER_VARIANT.AGENTS}
        href={LIGHTHOUSE_ROUTE.CHAT}
      />
    </div>
  </ContentLayout>
);
