import { FileBarChart } from "lucide-react";
import { Suspense } from "react";

import { getCompliancesOverview } from "@/actions/compliances";
import { getProviders } from "@/actions/providers/providers";
import { getScans } from "@/actions/scans";
import { auth } from "@/auth.config";
import {
  listReportRuns,
  listReportSchedules,
  listReportShareLinks,
  listReportTypes,
} from "@/cloudsneeker/actions/reports";
import { ReportCatalogGrid } from "@/cloudsneeker/components/report-catalog-grid";
import { ReportPageTabs } from "@/cloudsneeker/components/report-page-tabs";
import { ReportRunsTable } from "@/cloudsneeker/components/report-runs-table";
import { ReportSchedulesPanel } from "@/cloudsneeker/components/report-schedules-panel";
import { ReportShareLinksTable } from "@/cloudsneeker/components/report-share-links-table";
import {
  buildReportCatalog,
  reportTitle,
} from "@/cloudsneeker/lib/report-catalog";
import {
  frameworkOptions,
  latestScanPerProvider,
  providerOptions,
} from "@/cloudsneeker/lib/report-options";
import { getReportsTab, REPORTS_TAB } from "@/cloudsneeker/lib/report-tabs";
import type {
  ReportRunResource,
  ReportScheduleResource,
  ReportShareLinkResource,
  ReportTypeResource,
} from "@/cloudsneeker/types/reports";
import { Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";

/** Recent scans whose compliance overviews feed the framework list. */
const FRAMEWORK_SCAN_LIMIT = 5;

interface ReportsPageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function ReportsPage({ searchParams }: ReportsPageProps) {
  const resolvedSearchParams = await searchParams;
  const activeTab = getReportsTab(resolvedSearchParams.tab);

  return (
    <ContentLayout title="Reports" icon={<FileBarChart />}>
      <div className="mb-4">
        <p className="text-text-neutral-secondary max-w-3xl text-sm">
          Turn cloud, application, compliance, and governance results into
          reports for leadership, auditors, and engineering teams. Download
          them, share a secure link, or email them on a schedule.
        </p>
      </div>
      <Suspense fallback={<Skeleton className="h-64 w-full rounded-xl" />}>
        <SSRReportsWorkspace activeTab={activeTab} />
      </Suspense>
    </ContentLayout>
  );
}

const asList = <T,>(response: unknown): T[] => {
  const data = (response as { data?: unknown } | undefined)?.data;
  return Array.isArray(data) ? (data as T[]) : [];
};

const loadFrameworks = async () => {
  const scans = await getScans({
    filters: { "filter[state]": "completed" },
    sort: "-inserted_at",
    pageSize: 50,
    fields: { scans: "completed_at,provider" },
  });
  const scanIds = latestScanPerProvider(
    asList(scans),
    FRAMEWORK_SCAN_LIMIT,
  );
  const overviews = await Promise.all(
    scanIds.map((scanId) => getCompliancesOverview({ scanId })),
  );
  return frameworkOptions(
    overviews.map((overview) =>
      asList<{ id: string; attributes?: { framework?: string; version?: string } }>(
        overview,
      ),
    ),
  );
};

const SSRReportsWorkspace = async ({
  activeTab,
}: {
  activeTab: ReturnType<typeof getReportsTab>;
}) => {
  const session = await auth();
  const canManage = Boolean(session?.user?.permissions?.manage_scans);

  const [
    typesResponse,
    runsResponse,
    schedulesResponse,
    linksResponse,
    providersResponse,
    frameworks,
  ] = await Promise.all([
    listReportTypes(),
    listReportRuns({ "page[size]": "50", sort: "-inserted_at" }),
    canManage && activeTab === REPORTS_TAB.SCHEDULES
      ? listReportSchedules({ "page[size]": "100" })
      : Promise.resolve(undefined),
    canManage && activeTab === REPORTS_TAB.SHARE_LINKS
      ? listReportShareLinks({ "page[size]": "100", sort: "-inserted_at" })
      : Promise.resolve(undefined),
    getProviders({ pageSize: 100 }),
    loadFrameworks().catch(() => []),
  ]);

  const catalog = buildReportCatalog(asList<ReportTypeResource>(typesResponse));
  const runs = asList<ReportRunResource>(runsResponse);
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
        <div className="flex flex-col gap-8">
          <section className="flex flex-col gap-3">
            <h2 className="text-text-neutral-primary text-base font-semibold">
              Report catalog
            </h2>
            <ReportCatalogGrid
              catalog={catalog}
              providers={providers}
              frameworks={frameworks}
            />
          </section>
          <section className="flex flex-col gap-3">
            <h2 className="text-text-neutral-primary text-base font-semibold">
              Recent reports
            </h2>
            <ReportRunsTable runs={runs} canShare={canManage} />
          </section>
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
