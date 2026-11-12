import { ListChecks } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Suspense } from "react";

import { auth } from "@/auth.config";
import { listAreaFindings } from "@/cloudsneeker/actions/finding-triage";
import { listTrivyTargets } from "@/cloudsneeker/actions/trivy";
import { newAlertHref } from "@/cloudsneeker/lib/alert-areas";
import { securityCategoryTabs } from "@/cloudsneeker/lib/app-security-categories";
import {
  AREA_CONFIG,
  AREA_FINDING_SORT,
  AREA_FINDING_SORT_LABEL,
  AREA_FINDINGS_PAGE_SIZE,
  type AreaFindingFilters,
  areaFindingsPageHref,
  areaFindingsSearchParams,
  areaSortOptions,
  hasLegacyAreaParams,
  parseAreaFilters,
} from "@/cloudsneeker/lib/area-findings";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import type {
  AreaFindingResource,
  AreaFindingsResponse,
  AreaFindingSource,
  FindingArea,
} from "@/cloudsneeker/types/area-findings";
import type { TrivyTargetResource } from "@/cloudsneeker/types/trivy";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";

import { AreaFindingsFilters } from "./area-findings-filters";
import { AreaFindingsTable } from "./area-findings-table";
import { pagesOf } from "./area-triage-view";
import { EmptyState } from "./empty-state";
import { PageHeader } from "./page-header";
import { PageNav } from "./page-nav";
import { RiskPriorityFilter } from "./risk-priority-filter";
import { SectionCard } from "./section-card";
import { SecurityCategoryTabs } from "./security-category-tabs";
import { SortSelect } from "./standard/sort-select";
import { StandardTableCard } from "./standard/standard-table-card";

interface AreaFindingsViewProps {
  area: FindingArea;
  searchParams: SearchParamsProps;
}

const sourcesOf = (response: unknown): AreaFindingSource[] => {
  const sources = (response as { meta?: { sources?: unknown } } | undefined)
    ?.meta?.sources;
  return Array.isArray(sources) ? (sources as AreaFindingSource[]) : [];
};

/** Display name of an application (linked provider) from one of its targets. */
const loadApplicationName = async (
  providerId: string,
): Promise<string | undefined> => {
  const response = await listTrivyTargets({
    "filter[provider]": providerId,
    "page[size]": "1",
  });
  if (!isListResponse(response)) return undefined;
  const target = responseList<TrivyTargetResource>(response)[0];
  return (
    target?.attributes.provider_alias ||
    target?.attributes.provider_uid ||
    undefined
  );
};

const isFiltered = (filters: AreaFindingFilters): boolean =>
  filters.severities.length > 0 ||
  filters.triage !== null ||
  filters.source !== null ||
  filters.search !== "" ||
  filters.fix !== null ||
  Boolean(filters.exploited) ||
  Boolean(filters.category) ||
  Boolean(filters.priority) ||
  Boolean(filters.overdue) ||
  Boolean(filters.application) ||
  Boolean(filters.account) ||
  Boolean(filters.region) ||
  Boolean(filters.resourceType) ||
  Boolean(filters.muted);

/** One area's Findings page: current findings with filters and triage. */
export const AreaFindingsView = ({
  area,
  searchParams,
}: AreaFindingsViewProps) => {
  const config = AREA_CONFIG[area];
  const filters = parseAreaFilters(searchParams);
  // Old links (severity=, q=, account= ...) move to the filter bar's names.
  if (hasLegacyAreaParams(searchParams)) {
    redirect(areaFindingsPageHref(area, filters));
  }

  return (
    <ContentLayout title={`${config.name} findings`} icon={<ListChecks />}>
      <PageHeader
        description={`Open findings from the latest scan of each ${config.sourceLabel.toLowerCase()}. Set a triage status on one finding or many; it follows the finding across rescans.`}
        actions={
          <>
            <Button asChild size="sm" variant="outline">
              <Link href={config.triageHref}>Triage</Link>
            </Button>
            <Button asChild size="sm" variant="outline">
              <Link href={newAlertHref(area)}>Create alert</Link>
            </Button>
          </>
        }
      />
      <Suspense
        key={JSON.stringify(filters)}
        fallback={<Skeleton className="h-64 w-full rounded-xl" />}
      >
        <SSRAreaFindings area={area} filters={filters} />
      </Suspense>
    </ContentLayout>
  );
};

const SSRAreaFindings = async ({
  area,
  filters,
}: {
  area: FindingArea;
  filters: AreaFindingFilters;
}) => {
  const config = AREA_CONFIG[area];
  const [response, session] = await Promise.all([
    listAreaFindings(areaFindingsSearchParams(area, filters)),
    auth(),
  ]);
  const canTriage = Boolean(session?.user?.permissions?.manage_scans);

  if (!isListResponse(response)) {
    return (
      <SectionCard title="Findings">
        <EmptyState
          title="Findings could not be loaded"
          description="The service did not answer. Reload the page in a moment."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={areaFindingsPageHref(area, filters)}>Reload</Link>
            </Button>
          }
        />
      </SectionCard>
    );
  }

  const findings = responseList<AreaFindingResource>(response);
  const total = responseCount(response) ?? findings.length;
  const pages = pagesOf(response);
  const meta = (response as AreaFindingsResponse).meta;
  const applicationName = filters.application
    ? await loadApplicationName(filters.application)
    : undefined;

  const filtered = isFiltered(filters);
  const sortOptions = areaSortOptions(area).map((sort) => ({
    value: sort,
    label: AREA_FINDING_SORT_LABEL[sort],
  }));

  return (
    <div className="flex flex-col gap-6">
      {config.showCategory ? (
        <SecurityCategoryTabs
          area={area}
          filters={filters}
          tabs={securityCategoryTabs(
            meta?.category_counts,
            meta?.enabled_categories,
          )}
        />
      ) : null}
      {config.showCategory ? (
        <RiskPriorityFilter
          area={area}
          filters={filters}
          counts={meta?.priority_counts}
          overdueCount={meta?.overdue_count}
          applicationName={applicationName}
        />
      ) : null}
      <AreaFindingsFilters
        area={area}
        sources={sourcesOf(response)}
        sourceLabel={config.sourceLabel}
        facets={meta?.facets}
      />
      <StandardTableCard
        searchPlaceholder="Search rule, title or resource (press Enter)"
        total={total}
        toolbarRight={
          <SortSelect
            value={filters.sort}
            defaultValue={AREA_FINDING_SORT.SEVERITY}
            options={sortOptions}
          />
        }
        footer={
          <PageNav
            page={filters.page}
            pages={pages}
            count={total}
            noun="findings"
            pageSize={filters.pageSize ?? AREA_FINDINGS_PAGE_SIZE}
            hrefFor={(page) => areaFindingsPageHref(area, { ...filters, page })}
          />
        }
      >
        {findings.length === 0 ? (
          <EmptyState
            title={filtered ? "No findings match" : "No findings yet"}
            description={
              filtered
                ? "Clear a filter to see more findings."
                : config.emptyFindings
            }
            action={
              filtered ? (
                <Button asChild size="sm" variant="outline">
                  <Link href={areaFindingsPageHref(area, {})}>
                    Clear filters
                  </Link>
                </Button>
              ) : undefined
            }
          />
        ) : (
          <AreaFindingsTable
            config={config}
            findings={findings}
            canTriage={canTriage}
            query={areaFindingsSearchParams(area, filters)}
            total={total}
          />
        )}
      </StandardTableCard>
    </div>
  );
};
