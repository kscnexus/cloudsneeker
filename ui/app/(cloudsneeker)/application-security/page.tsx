import { ListChecks, Plus, ScanSearch, Tags } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { getFindings } from "@/actions/findings/findings";
import { getProviders } from "@/actions/providers/providers";
import { listAreaFindings } from "@/cloudsneeker/actions/finding-triage";
import { listTrivyRuns, listTrivyTargets } from "@/cloudsneeker/actions/trivy";
import { BRAND } from "@/cloudsneeker/brand";
import { AppSecurityDashboardPanel } from "@/cloudsneeker/components/app-security-dashboard-panel";
import { AppSecurityFixesCard } from "@/cloudsneeker/components/app-security-fixes-card";
import { AppSecurityInsights } from "@/cloudsneeker/components/app-security-insights";
import { AppSecurityRunList } from "@/cloudsneeker/components/app-security-run-list";
import { AppSecurityScanHistory } from "@/cloudsneeker/components/app-security-scan-history";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { ProductPageTabs } from "@/cloudsneeker/components/product-page-tabs";
import { ScanAllRepositoriesButton } from "@/cloudsneeker/components/scan-all-repositories-button";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import type { SeverityBreakdownItem } from "@/cloudsneeker/components/severity-breakdown";
import { TrivyTargetList } from "@/cloudsneeker/components/trivy-target-list";
import {
  APP_SECURITY_CATEGORIES,
  APP_SECURITY_CATEGORY_PARAM,
  APP_SECURITY_TAB,
  APP_SECURITY_TAB_PARAM,
  type AppSecurityCategory,
  type AppSecuritySource,
  type AppSecurityTab,
  appSecurityCategoryHref,
  appSecurityTabHref,
  buildAppSecurityDashboard,
  categoryDefinition,
  filterTargetsByCategory,
  getAppSecurityCategory,
  getAppSecurityTab,
  newTargetHref,
  repositorySourcesWithoutTarget,
} from "@/cloudsneeker/lib/app-security-dashboard";
import {
  getScanHistoryView,
  SCAN_HISTORY_PAGE_PARAM,
  SCAN_HISTORY_PARAM,
  type ScanHistoryView,
} from "@/cloudsneeker/lib/app-security-scan-history";
import { AREA_CONFIG } from "@/cloudsneeker/lib/area-findings";
import {
  appScanActivity,
  loadAreaTriageCounts,
} from "@/cloudsneeker/lib/dashboard-data";
import {
  appScanFindingTrend,
  buildRemediationProgress,
  rankTargetsByFindings,
} from "@/cloudsneeker/lib/dashboards";
import {
  isListResponse,
  openFindingsHref,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import { labelForProviderType } from "@/cloudsneeker/lib/trivy-modes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import {
  AREA_FIX_FILTER,
  type AreaFindingResource,
  type AreaFixFilter,
  FINDING_AREA,
} from "@/cloudsneeker/types/area-findings";
import {
  REPORT_SEVERITY_ORDER,
  type ReportSeverity,
} from "@/cloudsneeker/types/reports";
import type {
  TrivyRunResource,
  TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { FAIL_FILTER_VALUE, MUTED_FILTER } from "@/lib/findings-filters";
import { cn } from "@/lib/utils";
import type { SearchParamsProps } from "@/types";

/** Runs read for the KPIs; the dashboard shows the newest few. */
const DASHBOARD_RUN_PAGE_SIZE = "100";
const RECENT_RUN_LIMIT = 5;
const TOP_FIX_LIMIT = 5;
const TREND_DAYS = 30;
const APP_SECURITY_CONFIG = AREA_CONFIG[FINDING_AREA.APPLICATION_SECURITY];

interface ApplicationSecurityPageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function ApplicationSecurityPage({
  searchParams,
}: ApplicationSecurityPageProps) {
  const resolvedSearchParams = await searchParams;
  const activeCategory = getAppSecurityCategory(
    resolvedSearchParams[APP_SECURITY_CATEGORY_PARAM],
  );
  const activeTab = getAppSecurityTab(
    resolvedSearchParams[APP_SECURITY_TAB_PARAM],
    activeCategory,
  );

  return (
    <ContentLayout title={BRAND.appSecurityName} icon={<ScanSearch />}>
      <PageHeader description="Scan dependencies, source code, container images, Infrastructure as Code, secrets, SBOMs and Kubernetes clusters, and see how to fix what they find." />
      <Suspense fallback={<Skeleton className="h-96 w-full rounded-xl" />}>
        <SSRAppSecurityWorkspace
          activeCategory={activeCategory}
          activeTab={activeTab}
          historyView={getScanHistoryView(
            resolvedSearchParams[SCAN_HISTORY_PARAM],
          )}
          historyPage={resolvedSearchParams[SCAN_HISTORY_PAGE_PARAM]}
        />
      </Suspense>
    </ContentLayout>
  );
}

/** Open findings with (or without) a fix: the count, and the first few. */
const loadFixes = async (
  fix: AreaFixFilter,
  pageSize: number,
): Promise<{ count: number | null; findings: AreaFindingResource[] }> => {
  const response: unknown = await listAreaFindings({
    "filter[area]": FINDING_AREA.APPLICATION_SECURITY,
    "filter[fix]": fix,
    "page[size]": String(pageSize),
    sort: "severity",
  });
  if (!isListResponse(response)) return { count: null, findings: [] };
  return {
    count: responseCount(response),
    findings: responseList<AreaFindingResource>(response),
  };
};

const chipClass = (active: boolean) =>
  cn(
    "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
    active
      ? "border-button-primary bg-button-primary text-black"
      : "border-border-neutral-secondary text-text-neutral-secondary hover:text-text-neutral-primary",
  );

const workspaceActions = (
  <div className="flex flex-wrap gap-2">
    <Button asChild size="sm" variant="outline">
      <Link href={APP_SECURITY_CONFIG.findingsHref}>
        <ListChecks aria-hidden="true" />
        Findings
      </Link>
    </Button>
    <Button asChild size="sm" variant="outline">
      <Link href={APP_SECURITY_CONFIG.triageHref}>
        <Tags aria-hidden="true" />
        Triage
      </Link>
    </Button>
    <ScanAllRepositoriesButton />
    <Button asChild size="sm">
      <Link href={newTargetHref()}>
        <Plus aria-hidden="true" />
        New target
      </Link>
    </Button>
  </div>
);

/** Failed, unmuted findings per severity across the given scans. */
const loadSeverityTotals = async (
  scanIds: string[],
): Promise<SeverityBreakdownItem[] | null> => {
  if (scanIds.length === 0) return null;
  const scanFilter = scanIds.join(",");
  const baseFilters: Record<string, string> = {
    "filter[scan__in]": scanFilter,
    "filter[status__in]": FAIL_FILTER_VALUE,
    "filter[muted]": MUTED_FILTER.EXCLUDE,
  };

  const counts = await Promise.all(
    REPORT_SEVERITY_ORDER.map(async (severity: ReportSeverity) => {
      const response: unknown = await getFindings({
        page: 1,
        pageSize: 1,
        filters: { ...baseFilters, "filter[severity__in]": severity },
      });
      return responseCount(response);
    }),
  );
  if (counts.some((count) => count === null)) return null;

  return REPORT_SEVERITY_ORDER.map((severity, index) => ({
    severity,
    count: counts[index] ?? 0,
    href: openFindingsHref({
      "filter[scan__in]": scanFilter,
      "filter[severity__in]": severity,
    }),
  }));
};

/** Connected sources, labelled like the new-target form lists them. */
const loadSources = async (): Promise<AppSecuritySource[]> => {
  const response = await getProviders({ pageSize: 100 });
  return (response?.data ?? []).map((provider) => ({
    id: provider.id,
    providerType: provider.attributes.provider,
    label: provider.attributes.alias || provider.attributes.uid || provider.id,
  }));
};

const SSRAppSecurityWorkspace = async ({
  activeCategory,
  activeTab,
  historyView,
  historyPage,
}: {
  activeCategory: AppSecurityCategory | null;
  activeTab: AppSecurityTab;
  historyView: ScanHistoryView;
  historyPage: string | string[] | undefined;
}) => {
  const [
    targetsResponse,
    runsResponse,
    sources,
    fixable,
    unfixable,
    triageCounts,
  ] = await Promise.all([
    listTrivyTargets({ "page[size]": "100", sort: "-inserted_at" }),
    listTrivyRuns({
      "page[size]": DASHBOARD_RUN_PAGE_SIZE,
      sort: "-inserted_at",
    }),
    loadSources(),
    loadFixes(AREA_FIX_FILTER.AVAILABLE, TOP_FIX_LIMIT),
    loadFixes(AREA_FIX_FILTER.UNAVAILABLE, 1),
    loadAreaTriageCounts(FINDING_AREA.APPLICATION_SECURITY),
  ]);
  if (!isListResponse(targetsResponse)) {
    // A failed request must not read as "no targets yet".
    return (
      <SectionCard title="Targets">
        <EmptyState
          title="Targets could not be loaded"
          description="The service did not answer. Reload the page in a moment."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={appSecurityHref()}>Reload</Link>
            </Button>
          }
        />
      </SectionCard>
    );
  }
  const targets = responseList<TrivyTargetResource>(targetsResponse);
  const runs = responseList<TrivyRunResource>(runsResponse);
  const dashboard = buildAppSecurityDashboard({
    targets,
    runs,
    runTotal: responseCount(runsResponse),
  });
  const severityTotals = await loadSeverityTotals(dashboard.latestScanIds);
  const openTotal =
    fixable.count === null || unfixable.count === null
      ? null
      : fixable.count + unfixable.count;
  const unscannedRepositories = repositorySourcesWithoutTarget(
    sources,
    targets,
  );

  const visibleTargets = filterTargetsByCategory(targets, activeCategory);
  const activeDefinition = activeCategory
    ? categoryDefinition(activeCategory)
    : undefined;

  const connectedRepositories =
    unscannedRepositories.length > 0 ? (
      <SectionCard
        title="Connected repositories"
        description="These repositories are connected but not scanned here yet. Create a target to scan their dependencies, secrets and code."
      >
        <ul className="divide-border-neutral-secondary flex flex-col divide-y">
          {unscannedRepositories.map((source) => (
            <li
              key={source.id}
              className="flex items-center justify-between gap-4 py-3"
            >
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{source.label}</p>
                <p className="text-text-neutral-secondary text-xs">
                  {labelForProviderType(source.providerType)}
                </p>
              </div>
              <Button asChild size="sm" variant="outline">
                <Link href={newTargetHref(source.id)}>Create target</Link>
              </Button>
            </li>
          ))}
        </ul>
      </SectionCard>
    ) : null;

  const dashboardContent = (
    <div className="flex flex-col gap-6">
      {targets.length > 0 ? (
        <AppSecurityDashboardPanel
          dashboard={dashboard}
          severityTotals={severityTotals}
          activeCategory={null}
        />
      ) : (
        <EmptyState
          icon={<ScanSearch />}
          title="No targets yet"
          description="Create a target for a repository, image, archive or cluster to start scanning."
          action={
            <Button asChild size="sm">
              <Link href={newTargetHref()}>Create a target</Link>
            </Button>
          }
        />
      )}
      {targets.length > 0 ? (
        <AppSecurityInsights
          dashboard={dashboard}
          targets={targets}
          rankedTargets={rankTargetsByFindings(
            runs,
            new Set(targets.map((target) => target.id)),
          )}
          severityTotals={severityTotals}
          openTotal={openTotal}
          remediation={buildRemediationProgress(triageCounts)}
          trend={appScanFindingTrend(runs, TREND_DAYS)}
          failedScans={appScanActivity(runs)}
        />
      ) : null}
      {targets.length > 0 ? (
        <AppSecurityFixesCard
          fixable={fixable.count}
          unfixable={unfixable.count}
          topFixes={fixable.findings.map((finding) => finding.attributes)}
        />
      ) : null}
      {connectedRepositories}
      <SectionCard
        title="Recent scans"
        description="Newest first. Open a scan for its summary or jump to its findings."
        actions={
          <Button asChild variant="ghost" size="sm">
            <Link href={appSecurityTabHref(APP_SECURITY_TAB.SCANS)}>
              All scans
            </Link>
          </Button>
        }
      >
        <AppSecurityRunList
          runs={runs.slice(0, RECENT_RUN_LIMIT)}
          emptyMessage="No scans yet. Open a target and start a scan."
        />
      </SectionCard>
    </div>
  );

  const targetsContent = (
    <div className="flex flex-col gap-6">
      <SectionCard
        title={
          activeDefinition ? `Targets · ${activeDefinition.label}` : "Targets"
        }
        description={
          activeDefinition
            ? `${visibleTargets.length} of ${targets.length} targets. ${activeDefinition.description}`
            : "Each target is a source you scan on demand or on a schedule."
        }
      >
        <div className="flex flex-col gap-4">
          <nav aria-label="Scan type" className="flex flex-wrap gap-2">
            <Link
              href={appSecurityCategoryHref(null)}
              aria-current={activeCategory === null ? "page" : undefined}
              className={chipClass(activeCategory === null)}
            >
              All types
            </Link>
            {APP_SECURITY_CATEGORIES.map((category) => (
              <Link
                key={category.id}
                href={appSecurityCategoryHref(category.id)}
                aria-current={
                  activeCategory === category.id ? "page" : undefined
                }
                className={chipClass(activeCategory === category.id)}
              >
                {category.label}
              </Link>
            ))}
          </nav>
          {activeDefinition && visibleTargets.length === 0 ? (
            <EmptyState
              title={`No ${activeDefinition.label} targets yet`}
              description={activeDefinition.description}
              action={
                <Button asChild size="sm">
                  <Link href={appSecurityHref("new")}>Create a target</Link>
                </Button>
              }
            />
          ) : (
            <TrivyTargetList targets={visibleTargets} />
          )}
        </div>
      </SectionCard>
      {connectedRepositories}
    </div>
  );

  // Loaded only on the Scans tab: it pages through every target's history.
  const scansContent =
    activeTab === APP_SECURITY_TAB.SCANS ? (
      <Suspense fallback={<Skeleton className="h-64 w-full rounded-xl" />}>
        <AppSecurityScanHistory view={historyView} page={historyPage} />
      </Suspense>
    ) : null;

  return (
    <ProductPageTabs
      activeTab={activeTab}
      actions={workspaceActions}
      tabs={[
        {
          value: APP_SECURITY_TAB.DASHBOARD,
          label: "Dashboard",
          href: appSecurityTabHref(APP_SECURITY_TAB.DASHBOARD),
          content: dashboardContent,
        },
        {
          value: APP_SECURITY_TAB.TARGETS,
          label: "Targets",
          href: appSecurityTabHref(APP_SECURITY_TAB.TARGETS),
          content: targetsContent,
        },
        {
          value: APP_SECURITY_TAB.SCANS,
          label: "Scans",
          href: appSecurityTabHref(APP_SECURITY_TAB.SCANS),
          content: scansContent,
        },
      ]}
    />
  );
};
