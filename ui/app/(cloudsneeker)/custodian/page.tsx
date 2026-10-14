import { Shield } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

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
} from "@/cloudsneeker/lib/custodian-dashboard";
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
  const [policiesResponse, runsResponse] = await Promise.all([
    listCustodianPolicies({
      "page[size]": "100",
      sort: "-inserted_at",
    }),
    listCustodianRuns({
      "page[size]": "100",
      sort: "-inserted_at",
    }),
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
  const metrics = buildCustodianDashboard({ policies, runs });
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
