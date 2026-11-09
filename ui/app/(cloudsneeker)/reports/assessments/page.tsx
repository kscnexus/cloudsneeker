import { ShieldCheck } from "lucide-react";
import { Suspense } from "react";

import { getCompliancesOverview } from "@/actions/compliances";
import { getProviders } from "@/actions/providers/providers";
import { getScans } from "@/actions/scans";
import { listReportRuns } from "@/cloudsneeker/actions/reports";
import { AssessmentHistoryTable } from "@/cloudsneeker/components/assessment-history-table";
import { AssessmentWizard } from "@/cloudsneeker/components/assessment-wizard";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  ASSESSMENT_TYPE_IDS,
  scopeSources,
} from "@/cloudsneeker/lib/assessment-wizard";
import {
  frameworkOptions,
  latestScanPerProvider,
} from "@/cloudsneeker/lib/report-options";
import type { ReportRunResource } from "@/cloudsneeker/types/reports";
import { Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

/** Recent scans whose compliance overviews feed the framework list. */
const FRAMEWORK_SCAN_LIMIT = 5;

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
  const scanIds = latestScanPerProvider(asList(scans), FRAMEWORK_SCAN_LIMIT);
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

export default async function SecurityAssessmentsPage() {
  return (
    <ContentLayout title="Security assessments" icon={<ShieldCheck />}>
      <PageHeader description="Generate a security assessment for leadership, auditors, or engineering. Every figure comes from your latest scan results, with duplicates removed, coverage gaps labelled, and a quality check before the report is marked ready to share." />
      <Suspense fallback={<Skeleton className="h-96 w-full rounded-xl" />}>
        <SSRAssessments />
      </Suspense>
    </ContentLayout>
  );
}

const SSRAssessments = async () => {
  const [providersResponse, frameworks, runsResponse] = await Promise.all([
    getProviders({ pageSize: 100 }),
    loadFrameworks().catch(() => []),
    listReportRuns({
      "page[size]": "50",
      sort: "-inserted_at",
      "filter[report_type__in]": ASSESSMENT_TYPE_IDS.join(","),
    }),
  ]);
  const sources = scopeSources(providersResponse?.data ?? []);
  const runs = asList<ReportRunResource>(runsResponse);
  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        title="New assessment"
        description="Pick a report, its scope and period, and the sections to include."
      >
        <AssessmentWizard sources={sources} frameworks={frameworks} canGenerate />
      </SectionCard>
      <SectionCard
        title="Assessment history"
        description="Reports you can see under your role, newest first."
      >
        <AssessmentHistoryTable runs={runs} />
      </SectionCard>
    </div>
  );
};
