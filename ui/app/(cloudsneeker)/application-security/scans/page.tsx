import { Plus, ScanSearch } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { getFindings } from "@/actions/findings/findings";
import { getProviders } from "@/actions/providers/providers";
import { listTrivyRuns } from "@/cloudsneeker/actions/trivy";
import { BRAND } from "@/cloudsneeker/brand";
import { AppSecurityDashboardPanel } from "@/cloudsneeker/components/app-security-dashboard-panel";
import { AppSecurityScanHistory } from "@/cloudsneeker/components/app-security-scan-history";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { ScanAllRepositoriesButton } from "@/cloudsneeker/components/scan-all-repositories-button";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import type { SeverityBreakdownItem } from "@/cloudsneeker/components/severity-breakdown";
import { TrivyTargetList } from "@/cloudsneeker/components/trivy-target-list";
import {
  APP_SECURITY_CATEGORY_PARAM,
  type AppSecurityCategory,
  type AppSecuritySource,
  appSecurityCategoryHref,
  buildAppSecurityDashboard,
  categoryDefinition,
  filterTargetsByCategory,
  getAppSecurityCategory,
  newTargetHref,
  repositorySourcesWithoutTarget,
} from "@/cloudsneeker/lib/app-security-dashboard";
import {
  getScanHistoryView,
  SCAN_HISTORY_PAGE_PARAM,
  SCAN_HISTORY_PARAM,
  type ScanHistoryView,
} from "@/cloudsneeker/lib/app-security-scan-history";
import { APPSEC_SEGMENT } from "@/cloudsneeker/lib/appsec";
import {
  
  openFindingsHref,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import { labelForProviderType } from "@/cloudsneeker/lib/trivy-modes";
import { loadAllTargets } from "@/cloudsneeker/lib/trivy-targets-data";
import { appSecurityHref } from "@/cloudsneeker/routes";
import {
  REPORT_SEVERITY_ORDER,
  type ReportSeverity,
} from "@/cloudsneeker/types/reports";
import type {
  TrivyRunResource,
} from "@/cloudsneeker/types/trivy";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { FAIL_FILTER_VALUE, MUTED_FILTER } from "@/lib/findings-filters";
import type { SearchParamsProps } from "@/types";

/** Runs read for the KPIs. */
const DASHBOARD_RUN_PAGE_SIZE = "100";

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

  return (
    <ContentLayout
      title={`${BRAND.appSecurityName} scans`}
      icon={<ScanSearch />}
    >
      <PageHeader
        description="Targets are the repositories, container images, archives, SBOMs and clusters you scan, on demand or on a schedule. Each scan updates the findings and the software inventory of its target."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ScanAllRepositoriesButton />
            <Button asChild size="sm">
              <Link href={newTargetHref()}>
                <Plus aria-hidden="true" />
                New target
              </Link>
            </Button>
          </div>
        }
      />
      <Suspense fallback={<Skeleton className="h-96 w-full rounded-xl" />}>
        <SSRAppSecurityWorkspace
          activeCategory={activeCategory}
          historyView={getScanHistoryView(
            resolvedSearchParams[SCAN_HISTORY_PARAM],
          )}
          historyPage={resolvedSearchParams[SCAN_HISTORY_PAGE_PARAM]}
        />
      </Suspense>
    </ContentLayout>
  );
}

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
  historyView,
  historyPage,
}: {
  activeCategory: AppSecurityCategory | null;
  historyView: ScanHistoryView;
  historyPage: string | string[] | undefined;
}) => {
  const [loadedTargets, runsResponse, sources] = await Promise.all([
    loadAllTargets(),
    listTrivyRuns({
      "page[size]": DASHBOARD_RUN_PAGE_SIZE,
      sort: "-inserted_at",
    }),
    loadSources(),
  ]);
  if (!loadedTargets) {
    // A failed request must not read as "no targets yet".
    return (
      <SectionCard title="Targets">
        <EmptyState
          title="Targets could not be loaded"
          description="The service did not answer. Reload the page in a moment."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={appSecurityHref(APPSEC_SEGMENT.SCANS)}>Reload</Link>
            </Button>
          }
        />
      </SectionCard>
    );
  }
  const targets = loadedTargets.targets;
  const runs = responseList<TrivyRunResource>(runsResponse);
  const dashboard = buildAppSecurityDashboard({
    targets,
    runs,
    runTotal: responseCount(runsResponse),
  });
  const severityTotals = await loadSeverityTotals(dashboard.latestScanIds);
  const unscannedRepositories = repositorySourcesWithoutTarget(
    sources,
    targets,
  );

  const visibleTargets = filterTargetsByCategory(targets, activeCategory);
  const activeDefinition = activeCategory
    ? categoryDefinition(activeCategory)
    : undefined;

  return (
    <div className="flex flex-col gap-6">
      {targets.length > 0 ? (
        <AppSecurityDashboardPanel
          dashboard={dashboard}
          severityTotals={severityTotals}
          activeCategory={activeCategory}
        />
      ) : null}

      {unscannedRepositories.length > 0 ? (
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
      ) : null}

      <SectionCard
        title={
          activeDefinition ? `Targets · ${activeDefinition.label}` : "Targets"
        }
        description={
          activeDefinition
            ? `${visibleTargets.length} of ${targets.length} targets. ${activeDefinition.description}`
            : "Each target is a source you scan on demand or on a schedule."
        }
        actions={
          activeDefinition ? (
            <Button asChild variant="ghost" size="sm">
              <Link href={appSecurityCategoryHref(null)}>Show all targets</Link>
            </Button>
          ) : null
        }
      >
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
      </SectionCard>

      <Suspense fallback={<Skeleton className="h-64 w-full rounded-xl" />}>
        <AppSecurityScanHistory view={historyView} page={historyPage} />
      </Suspense>
    </div>
  );
};
