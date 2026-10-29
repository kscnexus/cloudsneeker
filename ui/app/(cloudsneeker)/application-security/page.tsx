import { Plus, ScanSearch } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { getFindings } from "@/actions/findings/findings";
import {
  listTrivyRuns,
  listTrivyTargets,
} from "@/cloudsneeker/actions/trivy";
import { BRAND } from "@/cloudsneeker/brand";
import { AppSecurityDashboardPanel } from "@/cloudsneeker/components/app-security-dashboard-panel";
import { AppSecurityRunList } from "@/cloudsneeker/components/app-security-run-list";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import type { SeverityBreakdownItem } from "@/cloudsneeker/components/severity-breakdown";
import { TrivyTargetList } from "@/cloudsneeker/components/trivy-target-list";
import {
  APP_SECURITY_CATEGORY_PARAM,
  type AppSecurityCategory,
  appSecurityCategoryHref,
  buildAppSecurityDashboard,
  categoryDefinition,
  filterTargetsByCategory,
  getAppSecurityCategory,
} from "@/cloudsneeker/lib/app-security-dashboard";
import {
  openFindingsHref,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import { appSecurityHref } from "@/cloudsneeker/routes";
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
import type { SearchParamsProps } from "@/types";

/** Runs read for the KPIs; the list shows the newest few. */
const DASHBOARD_RUN_PAGE_SIZE = "100";
const RECENT_RUN_LIMIT = 10;

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
    <ContentLayout title={BRAND.appSecurityName} icon={<ScanSearch />}>
      <PageHeader
        description="Scan dependencies, source code, container images, Infrastructure as Code, secrets, SBOMs and Kubernetes clusters. Results land in Findings next to your cloud security results."
        actions={
          <Button asChild size="sm">
            <Link href={appSecurityHref("new")}>
              <Plus aria-hidden="true" />
              New target
            </Link>
          </Button>
        }
      />
      <Suspense fallback={<Skeleton className="h-96 w-full rounded-xl" />}>
        <SSRAppSecurityWorkspace activeCategory={activeCategory} />
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

const SSRAppSecurityWorkspace = async ({
  activeCategory,
}: {
  activeCategory: AppSecurityCategory | null;
}) => {
  const [targetsResponse, runsResponse] = await Promise.all([
    listTrivyTargets({ "page[size]": "100", sort: "-inserted_at" }),
    listTrivyRuns({ "page[size]": DASHBOARD_RUN_PAGE_SIZE, sort: "-inserted_at" }),
  ]);
  const targets = responseList<TrivyTargetResource>(targetsResponse);
  const runs = responseList<TrivyRunResource>(runsResponse);
  const dashboard = buildAppSecurityDashboard({
    targets,
    runs,
    runTotal: responseCount(runsResponse),
  });
  const severityTotals = await loadSeverityTotals(dashboard.latestScanIds);

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

      <SectionCard
        title={activeDefinition ? `Targets · ${activeDefinition.label}` : "Targets"}
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

      <SectionCard
        title="Recent scans"
        description="Newest first. Open a scan for its summary or jump to its findings."
      >
        <AppSecurityRunList
          runs={runs.slice(0, RECENT_RUN_LIMIT)}
          emptyMessage="No scans yet. Open a target and start a scan."
        />
      </SectionCard>
    </div>
  );
};
