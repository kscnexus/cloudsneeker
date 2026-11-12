import { LibraryBig, Plus, Shield, Sparkles } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { getLatestFindings } from "@/actions/findings/findings";
import {
  listCustodianPolicies,
  listCustodianRuns,
} from "@/cloudsneeker/actions/custodian";
import { BRAND } from "@/cloudsneeker/brand";
import { CustodianDashboardPanel } from "@/cloudsneeker/components/custodian-dashboard-panel";
import { CustodianPageTabs } from "@/cloudsneeker/components/custodian-page-tabs";
import { CustodianPolicyList } from "@/cloudsneeker/components/custodian-policy-list";
import { CustodianReportsTable } from "@/cloudsneeker/components/custodian-reports-table";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { GovernanceInsights } from "@/cloudsneeker/components/governance-insights";
import {
  ListFilterBar,
  ListPager,
} from "@/cloudsneeker/components/list-filter-bar";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  buildCustodianDashboard,
  buildCustodianReportRows,
  CUSTODIAN_TAB,
  getCustodianTab,
  type CustodianFindingSuggestion,
} from "@/cloudsneeker/lib/custodian-dashboard";
import {
  generateHref,
  libraryHref,
} from "@/cloudsneeker/lib/custodian-library";
import {
  allMappedProwlerCheckIds,
  findingsHrefForChecks,
  templatesForProwlerChecks,
} from "@/cloudsneeker/lib/custodian-templates";
import {
  loadAreaTriageCounts,
  loadComplianceFrameworks,
  loadProviderCounts,
  loadProviderFindings,
} from "@/cloudsneeker/lib/dashboard-data";
import {
  buildRemediationProgress,
  summarizeCompliance,
} from "@/cloudsneeker/lib/dashboards";
import {
  hasListFilters,
  LIST_PARAM,
  type ListFilters,
  paginationOf,
  POLICY_SCHEDULE,
  parseListFilters,
  policyListQuery,
  runListQuery,
} from "@/cloudsneeker/lib/list-filters";
import { governanceHref, PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";
import {
  CUSTODIAN_RUN_STATUS,
  type CustodianPolicyResource,
  type CustodianRunResource,
} from "@/cloudsneeker/types/custodian";
import { Button, Skeleton } from "@/components/shadcn";
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
  const listFilters = parseListFilters(resolvedSearchParams);

  return (
    <ContentLayout title={BRAND.governanceName} icon={<Shield />}>
      <PageHeader description="Compliance across frameworks, cloud policy violations and audit readiness in one place. Policies run as dry-runs; apply mode is disabled." />
      <Suspense fallback={<Skeleton className="h-64 w-full rounded-xl" />}>
        <SSRCustodianWorkspace
          activeTab={activeTab}
          listFilters={listFilters}
        />
      </Suspense>
    </ContentLayout>
  );
}

const SSRCustodianWorkspace = async ({
  activeTab,
  listFilters,
}: {
  activeTab: ReturnType<typeof getCustodianTab>;
  listFilters: ListFilters;
}) => {
  const mappedChecks = allMappedProwlerCheckIds();
  const [
    policiesResponse,
    runsResponse,
    findingsResponse,
    frameworks,
    providerFindings,
    providerCounts,
    cloudTriage,
  ] = await Promise.all([
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
    loadComplianceFrameworks(),
    loadProviderFindings(),
    loadProviderCounts(),
    loadAreaTriageCounts(FINDING_AREA.CLOUD),
  ]);
  // Policies and Reports tabs: one filtered page from the API (the dashboard
  // above keeps its newest-100 sample for the charts).
  const [policyPage, runPage] = await Promise.all([
    activeTab === CUSTODIAN_TAB.POLICIES
      ? listCustodianPolicies(policyListQuery(listFilters))
      : Promise.resolve(null),
    activeTab === CUSTODIAN_TAB.REPORTS
      ? listCustodianRuns(runListQuery(listFilters))
      : Promise.resolve(null),
  ]);

  const policyError =
    policiesResponse && "error" in policiesResponse
      ? policiesResponse.error
      : null;
  const runError =
    runsResponse && "error" in runsResponse ? runsResponse.error : null;

  if (policyError || runError) {
    return (
      <EmptyState
        icon={<Shield />}
        title={`Unable to load ${BRAND.governanceName}`}
        description={
          typeof policyError === "string"
            ? policyError
            : typeof runError === "string"
              ? runError
              : "Try again in a moment."
        }
      />
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
  const findingSuggestions: CustodianFindingSuggestion[] =
    templatesForProwlerChecks(Array.from(failedCheckIds)).flatMap((template) =>
      template.prowlerCheckIds
        .filter((checkId) => failedCheckIds.has(checkId))
        .map((checkId) => ({
          checkId,
          templateId: template.id,
          templateName: template.name,
          providerType: template.providerTypes[0] ?? "aws",
          findingsHref: findingsHrefForChecks([checkId]) ?? "/findings",
          newPolicyHref: `${governanceHref("new")}?template=${template.id}`,
        })),
    );

  const metrics = buildCustodianDashboard({
    policies,
    runs,
    findingSuggestions,
  });
  const pagedPolicies = (
    policyPage && "data" in policyPage ? policyPage.data : []
  ) as CustodianPolicyResource[];
  const pagedRuns = (
    runPage && "data" in runPage ? runPage.data : []
  ) as CustodianRunResource[];
  const reportRows = buildCustodianReportRows({
    policies,
    runs: pagedRuns,
  });
  const providerOptions = new Map<string, string>();
  for (const policy of policies) {
    providerOptions.set(
      policy.attributes.provider_id,
      policy.attributes.provider_alias ||
        policy.attributes.provider_uid ||
        policy.attributes.provider_id,
    );
  }
  const providerSelect = {
    name: LIST_PARAM.PROVIDER,
    label: "Cloud account",
    allLabel: "All accounts",
    options: Array.from(providerOptions, ([value, label]) => ({
      value,
      label,
    })).sort((left, right) => left.label.localeCompare(right.label)),
  } as const;

  return (
    <CustodianPageTabs
      activeTab={activeTab}
      actions={
        <div className="flex flex-wrap gap-2">
          <Button asChild size="sm" variant="outline">
            <Link href={libraryHref()}>
              <LibraryBig aria-hidden="true" />
              Policy library
            </Link>
          </Button>
          <Button asChild size="sm" variant="outline">
            <Link href={generateHref()}>
              <Sparkles aria-hidden="true" />
              Generate with AI
            </Link>
          </Button>
          <Button asChild size="sm">
            <Link href={governanceHref("new")}>
              <Plus aria-hidden="true" />
              Create policy
            </Link>
          </Button>
        </div>
      }
      dashboardContent={
        <div className="flex flex-col gap-6">
          <GovernanceInsights
            frameworks={frameworks}
            compliance={frameworks ? summarizeCompliance(frameworks) : null}
            providerFindings={providerFindings}
            accountCount={providerCounts?.total ?? null}
            riskDecisions={buildRemediationProgress(cloudTriage)}
          />
          <section
            aria-labelledby="cloud-policies-heading"
            className="flex flex-col gap-3"
          >
            <h2
              id="cloud-policies-heading"
              className="text-text-neutral-primary text-base font-semibold"
            >
              Cloud policies
            </h2>
            <CustodianDashboardPanel metrics={metrics} />
          </section>
        </div>
      }
      policiesContent={
        <div className="flex flex-col gap-4">
          <ListFilterBar
            path={PRODUCT_ROUTE.GOVERNANCE}
            keep={{ tab: CUSTODIAN_TAB.POLICIES }}
            filters={listFilters}
            searchPlaceholder="Policy name or description"
            selects={[
              providerSelect,
              {
                name: LIST_PARAM.TYPE,
                label: "Schedule",
                allLabel: "Any schedule",
                options: [
                  { value: POLICY_SCHEDULE.ON, label: "Scheduled" },
                  { value: POLICY_SCHEDULE.OFF, label: "Not scheduled" },
                ],
              },
            ]}
          />
          <CustodianPolicyList
            policies={pagedPolicies}
            filtered={hasListFilters(listFilters)}
          />
          <ListPager
            path={PRODUCT_ROUTE.GOVERNANCE}
            keep={{ tab: CUSTODIAN_TAB.POLICIES }}
            filters={listFilters}
            pagination={paginationOf(policyPage, listFilters.page)}
            noun="policies"
          />
        </div>
      }
      reportsContent={
        <SectionCard
          title="Dry-run reports"
          description="Every dry-run with its policy, provider, duration and matched resources."
        >
          <div className="flex flex-col gap-4">
            <ListFilterBar
              path={PRODUCT_ROUTE.GOVERNANCE}
              keep={{ tab: CUSTODIAN_TAB.REPORTS }}
              filters={listFilters}
              searchPlaceholder="Policy name"
              selects={[
                providerSelect,
                {
                  name: LIST_PARAM.STATUS,
                  label: "Status",
                  allLabel: "All statuses",
                  options: Object.values(CUSTODIAN_RUN_STATUS).map((value) => ({
                    value,
                    label: value.charAt(0).toUpperCase() + value.slice(1),
                  })),
                },
              ]}
            />
            <CustodianReportsTable rows={reportRows} />
            <ListPager
              path={PRODUCT_ROUTE.GOVERNANCE}
              keep={{ tab: CUSTODIAN_TAB.REPORTS }}
              filters={listFilters}
              pagination={paginationOf(runPage, listFilters.page)}
              noun="dry-runs"
            />
          </div>
        </SectionCard>
      }
    />
  );
};
