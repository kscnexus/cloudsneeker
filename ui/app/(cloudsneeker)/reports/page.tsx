import { FileBarChart, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { getCompliancesOverview } from "@/actions/compliances";
import { getAllProviders } from "@/actions/providers/providers";
import { getScans } from "@/actions/scans";
import { auth } from "@/auth.config";
import {
  listReportRuns,
  listReportSchedules,
  listReportShareLinks,
  listReportTypes,
} from "@/cloudsneeker/actions/reports";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { PageNav } from "@/cloudsneeker/components/page-nav";
import { ReportCatalogGrid } from "@/cloudsneeker/components/report-catalog-grid";
import { ReportPageTabs } from "@/cloudsneeker/components/report-page-tabs";
import { ReportRunsTable } from "@/cloudsneeker/components/report-runs-table";
import { ReportSchedulesPanel } from "@/cloudsneeker/components/report-schedules-panel";
import { ReportShareLinksTable } from "@/cloudsneeker/components/report-share-links-table";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { StandardFilters } from "@/cloudsneeker/components/standard/standard-filters";
import { isAssessmentType } from "@/cloudsneeker/lib/assessment-wizard";
import {
  buildReportCatalog,
  reportTitle,
} from "@/cloudsneeker/lib/report-catalog";
import {
  frameworkOptions,
  latestScanPerProvider,
  providersWithoutFrameworks,
  providerOptions,
} from "@/cloudsneeker/lib/report-options";
import { getReportsTab, REPORTS_TAB } from "@/cloudsneeker/lib/report-tabs";
import {
  filterParam,
  readFilterList,
  readFilterValue,
  readPage,
  readPageSize,
  STANDARD_PARAM,
} from "@/cloudsneeker/lib/standard-list";
import { reportsHref } from "@/cloudsneeker/routes";
import {
  REPORT_RUN_STATUS,
  type ReportRunResource,
  type ReportScheduleResource,
  type ReportShareLinkResource,
  type ReportTypeResource,
} from "@/cloudsneeker/types/reports";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";

/** Recent scans whose compliance overviews feed the framework list. */
const FRAMEWORK_SCAN_LIMIT = 5;

const RUNS_PAGE_SIZE = 20;

const RUN_TRIGGER_OPTIONS = [
  { value: "manual", label: "On demand" },
  { value: "scheduled", label: "Scheduled" },
];

/** Recent reports list state (`filter[...]`, `page`, `pageSize`). */
interface RunListState {
  types: string[];
  status: string;
  trigger: string;
  page: number;
  pageSize: number;
}

const runListQuery = (state: RunListState): Record<string, string> => ({
  "page[size]": String(state.pageSize),
  "page[number]": String(state.page),
  sort: "-inserted_at",
  ...(state.types.length
    ? { "filter[report_type__in]": state.types.join(",") }
    : {}),
  ...(state.status ? { "filter[status]": state.status } : {}),
  ...(state.trigger ? { "filter[trigger]": state.trigger } : {}),
});

const runListHref = (state: RunListState, page: number): string => {
  const query = new URLSearchParams();
  if (state.types.length)
    query.set(filterParam("report_type__in"), state.types.join(","));
  if (state.status) query.set(filterParam("status"), state.status);
  if (state.trigger) query.set(filterParam("trigger"), state.trigger);
  if (state.pageSize !== RUNS_PAGE_SIZE)
    query.set(STANDARD_PARAM.PAGE_SIZE, String(state.pageSize));
  if (page > 1) query.set(STANDARD_PARAM.PAGE, String(page));
  const serialized = query.toString();
  return serialized ? `${reportsHref()}?${serialized}` : reportsHref();
};

const pagesOfResponse = (
  response: unknown,
): { pages: number; count: number } => {
  const pagination = (
    response as
      | { meta?: { pagination?: { pages?: number; count?: number } } }
      | undefined
  )?.meta?.pagination;
  return {
    pages: pagination?.pages && pagination.pages > 0 ? pagination.pages : 1,
    count: pagination?.count ?? 0,
  };
};

interface ReportsPageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function ReportsPage({ searchParams }: ReportsPageProps) {
  const resolvedSearchParams = await searchParams;
  const activeTab = getReportsTab(resolvedSearchParams.tab);
  const runList: RunListState = {
    types: readFilterList(resolvedSearchParams, "report_type__in"),
    status: readFilterValue(resolvedSearchParams, "status"),
    trigger: readFilterValue(resolvedSearchParams, "trigger"),
    page: readPage(resolvedSearchParams),
    pageSize: readPageSize(resolvedSearchParams, RUNS_PAGE_SIZE),
  };

  return (
    <ContentLayout title="Reports" icon={<FileBarChart />}>
      <PageHeader description="Turn cloud, application, compliance, and governance results into reports for leadership, auditors, and engineering teams. Download them, share a secure link, or email them on a schedule." />
      <Suspense fallback={<Skeleton className="h-64 w-full rounded-xl" />}>
        <SSRReportsWorkspace activeTab={activeTab} runList={runList} />
      </Suspense>
    </ContentLayout>
  );
}

const asList = <T,>(response: unknown): T[] => {
  const data = (response as { data?: unknown } | undefined)?.data;
  return Array.isArray(data) ? (data as T[]) : [];
};

const loadFrameworks = async (
  providers: Promise<Awaited<ReturnType<typeof getAllProviders>>>,
) => {
  const [scans, providerList] = await Promise.all([
    getScans({
      filters: { "filter[state]": "completed" },
      sort: "-inserted_at",
      pageSize: 50,
      fields: { scans: "completed_at,provider" },
    }),
    providers,
  ]);
  const skip = providersWithoutFrameworks(providerList?.data ?? []);
  const scanIds = latestScanPerProvider(
    asList(scans),
    FRAMEWORK_SCAN_LIMIT,
    skip,
  );
  const overviews = await Promise.all(
    scanIds.map((scanId) => getCompliancesOverview({ scanId })),
  );
  return frameworkOptions(
    overviews.map((overview) =>
      asList<{
        id: string;
        attributes?: { framework?: string; version?: string };
      }>(overview),
    ),
  );
};

const SSRReportsWorkspace = async ({
  activeTab,
  runList,
}: {
  activeTab: ReturnType<typeof getReportsTab>;
  runList: RunListState;
}) => {
  const session = await auth();
  const canManage = Boolean(session?.user?.permissions?.manage_scans);

  // Every page: Application Security targets alone can exceed one page.
  const providersRequest = getAllProviders();
  const [
    typesResponse,
    runsResponse,
    schedulesResponse,
    linksResponse,
    providersResponse,
    frameworks,
  ] = await Promise.all([
    listReportTypes(),
    listReportRuns(runListQuery(runList)),
    canManage && activeTab === REPORTS_TAB.SCHEDULES
      ? listReportSchedules({ "page[size]": "100" })
      : Promise.resolve(undefined),
    canManage && activeTab === REPORTS_TAB.SHARE_LINKS
      ? listReportShareLinks({ "page[size]": "100", sort: "-inserted_at" })
      : Promise.resolve(undefined),
    providersRequest,
    loadFrameworks(providersRequest).catch(() => []),
  ]);

  const catalog = buildReportCatalog(asList<ReportTypeResource>(typesResponse));
  // Assessments have their own wizard; the catalog keeps the focused reports.
  const focusedCatalog = catalog.filter((entry) => !isAssessmentType(entry.id));
  const runs = asList<ReportRunResource>(runsResponse);
  const runPages = pagesOfResponse(runsResponse);
  const schedules = asList<ReportScheduleResource>(schedulesResponse);
  const links = asList<ReportShareLinkResource>(linksResponse);
  const providers = providerOptions(providersResponse?.data ?? []);
  const runNames = Object.fromEntries(
    runs.map((run) => [
      run.id,
      reportTitle(run.attributes.report_type, run.attributes.report_name),
    ]),
  );

  return (
    <ReportPageTabs
      activeTab={activeTab}
      reportsContent={
        <div className="flex flex-col gap-6">
          <SectionCard
            title="Security assessments"
            description="Executive, application security, cloud security, and governance and compliance assessments with a remediation roadmap and a quality check before sharing."
            actions={
              <Button asChild size="sm">
                <Link href={reportsHref("assessments")}>
                  <ShieldCheck aria-hidden="true" />
                  New assessment
                </Link>
              </Button>
            }
          >
            <p className="text-text-neutral-secondary text-sm">
              A guided wizard picks the report type, scope, period, and
              sections, then shows progress, coverage warnings, and the quality
              result before you download the PDF and CSV.
            </p>
          </SectionCard>
          <SectionCard
            title="Report catalog"
            description="Pick a report, set its scope, and generate it."
          >
            <ReportCatalogGrid
              catalog={focusedCatalog}
              providers={providers}
              frameworks={frameworks}
            />
          </SectionCard>
          <SectionCard
            title="Recent reports"
            description="Open, download, or share a generated report."
          >
            <div className="flex flex-col gap-4">
              <StandardFilters
                testIdPrefix="report-runs"
                filters={[
                  {
                    key: "report_type__in",
                    label: "Report Types",
                    wide: true,
                    options: catalog.map((entry) => ({
                      value: entry.id,
                      label: entry.title,
                    })),
                  },
                  {
                    key: "status",
                    label: "Statuses",
                    single: true,
                    options: Object.values(REPORT_RUN_STATUS).map((value) => ({
                      value,
                      label: value.charAt(0).toUpperCase() + value.slice(1),
                    })),
                  },
                  {
                    key: "trigger",
                    label: "Triggers",
                    single: true,
                    options: RUN_TRIGGER_OPTIONS,
                  },
                ]}
              />
              <ReportRunsTable runs={runs} canShare={canManage} />
              <PageNav
                page={runList.page}
                pages={runPages.pages}
                count={runPages.count}
                noun="reports"
                pageSize={runList.pageSize}
                hrefFor={(page) => runListHref(runList, page)}
              />
            </div>
          </SectionCard>
        </div>
      }
      schedulesContent={
        <ReportSchedulesPanel
          schedules={schedules}
          catalog={catalog}
          providers={providers}
          frameworks={frameworks}
          canManage={canManage}
        />
      }
      shareLinksContent={
        <ReportShareLinksTable
          links={links}
          runNames={runNames}
          canManage={canManage}
        />
      }
    />
  );
};
