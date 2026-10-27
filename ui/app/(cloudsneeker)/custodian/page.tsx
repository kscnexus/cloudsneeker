import { Shield } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { getLatestFindings } from "@/actions/findings/findings";
import {
  listCustodianPolicies,
  listCustodianRuns,
} from "@/cloudsneeker/actions/custodian";
import { CustodianDashboardPanel } from "@/cloudsneeker/components/custodian-dashboard-panel";
import { CustodianPageTabs } from "@/cloudsneeker/components/custodian-page-tabs";
import { CustodianPolicyList } from "@/cloudsneeker/components/custodian-policy-list";
import { CustodianReportsTable } from "@/cloudsneeker/components/custodian-reports-table";
import {
  buildCustodianDashboard,
  buildCustodianReportRows,
  getCustodianTab,
  type CustodianFindingSuggestion,
} from "@/cloudsneeker/lib/custodian-dashboard";
import {
  allMappedProwlerCheckIds,
  findingsHrefForChecks,
  templatesForProwlerChecks,
} from "@/cloudsneeker/lib/custodian-templates";
import type {
  CustodianPolicyResource,
  CustodianRunResource,
} from "@/cloudsneeker/types/custodian";
import { Button, Skeleton } from "@/components/shadcn";
import { Card, CardContent } from "@/components/shadcn/card/card";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";

interface CustodianPageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function CustodianPage({
  searchParams,
}: CustodianPageProps) {
  const resolvedSearchParams = await searchParams;
  const activeTab = getCustodianTab(resolvedSearchParams.tab);

  return (
    <ContentLayout title="Cloud Custodian" icon={<Shield />}>
      <div className="mb-4">
        <p className="text-text-neutral-secondary text-sm">
          Manage Cloud Custodian policies, review dry-run reports, and track
          matched resources. Apply mode is disabled.
        </p>
      </div>
      <Suspense fallback={<Skeleton className="h-64 w-full rounded-xl" />}>
        <SSRCustodianWorkspace activeTab={activeTab} />
      </Suspense>
    </ContentLayout>
  );
}

const SSRCustodianWorkspace = async ({
  activeTab,
}: {
  activeTab: ReturnType<typeof getCustodianTab>;
}) => {
  const mappedChecks = allMappedProwlerCheckIds();
  const [policiesResponse, runsResponse, findingsResponse] = await Promise.all([
    listCustodianPolicies({
      "page[size]": "100",
      sort: "-inserted_at",
    }),
    listCustodianRuns({
      "page[size]": "100",
      sort: "-inserted_at",
    }),
    mappedChecks.length > 0
      ? getLatestFindings({
          page: 1,
          pageSize: 25,
          filters: {
            "filter[status]": "FAIL",
            "filter[check_id__in]": mappedChecks.join(","),
          },
        })
      : Promise.resolve(undefined),
  ]);

  const policyError =
    policiesResponse && "error" in policiesResponse
      ? policiesResponse.error
      : null;
  const runError =
    runsResponse && "error" in runsResponse ? runsResponse.error : null;

  if (policyError || runError) {
    return (
      <p className="text-text-error text-sm">
        {typeof policyError === "string"
          ? policyError
          : typeof runError === "string"
            ? runError
            : "Unable to load Custodian workspace."}
      </p>
    );
  }

  const policies = (policiesResponse?.data ?? []) as CustodianPolicyResource[];
  const runs = (runsResponse?.data ?? []) as CustodianRunResource[];

  const failedCheckIds = new Set<string>();
  const findingsData = findingsResponse?.data;
  if (Array.isArray(findingsData)) {
    for (const finding of findingsData) {
      const checkId = (finding as { attributes?: { check_id?: string } })
        ?.attributes?.check_id;
      if (checkId) failedCheckIds.add(checkId);
    }
  }
  const findingSuggestions: CustodianFindingSuggestion[] = templatesForProwlerChecks(
    Array.from(failedCheckIds),
  ).flatMap((template) =>
    template.prowlerCheckIds
      .filter((checkId) => failedCheckIds.has(checkId))
      .map((checkId) => ({
        checkId,
        templateId: template.id,
        templateName: template.name,
        providerType: template.providerTypes[0] ?? "aws",
        findingsHref: findingsHrefForChecks([checkId]) ?? "/findings",
        newPolicyHref: `/custodian/new?template=${template.id}`,
      })),
  );

  const metrics = buildCustodianDashboard({
    policies,
    runs,
    findingSuggestions,
  });
  const reportRows = buildCustodianReportRows({ policies, runs });

  return (
    <CustodianPageTabs
      activeTab={activeTab}
      actions={
        <Button asChild size="sm">
          <Link href="/custodian/new">Create policy</Link>
        </Button>
      }
      dashboardContent={<CustodianDashboardPanel metrics={metrics} />}
      policiesContent={<CustodianPolicyList policies={policies} />}
      reportsContent={
        <Card variant="base" padding="none" className="w-full shadow-sm">
          <CardContent className="p-4">
            <CustodianReportsTable rows={reportRows} />
          </CardContent>
        </Card>
      }
    />
  );
};
