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
import { ReportCatalogGrid } from "@/cloudsneeker/components/report-catalog-grid";
import { ReportPageTabs } from "@/cloudsneeker/components/report-page-tabs";
import { ReportRunsTable } from "@/cloudsneeker/components/report-runs-table";
import { ReportSchedulesPanel } from "@/cloudsneeker/components/report-schedules-panel";
import { ReportShareLinksTable } from "@/cloudsneeker/components/report-share-links-table";
import { SectionCard } from "@/cloudsneeker/components/section-card";
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
import { reportsHref } from "@/cloudsneeker/routes";
import type {
  ReportRunResource,
  ReportScheduleResource,
  ReportShareLinkResource,
  ReportTypeResource,
} from "@/cloudsneeker/types/reports";
import { Button, Skeleton } from "@/components/shadcn";
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
      <PageHeader description="Turn cloud, application, compliance, and governance results into reports for leadership, auditors, and engineering teams. Download them, share a secure link, or email them on a schedule." />
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
}: {
  activeTab: ReturnType<typeof getReportsTab>;
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
    listReportRuns({ "page[size]": "50", sort: "-inserted_at" }),
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
            <ReportRunsTable runs={runs} canShare={canManage} />
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
