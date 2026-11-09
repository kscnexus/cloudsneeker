import { ListChecks } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { auth } from "@/auth.config";
import { listAreaFindings } from "@/cloudsneeker/actions/finding-triage";
import {
  AREA_CONFIG,
  type AreaFindingFilters,
  areaFindingsPageHref,
  areaFindingsSearchParams,
  parseAreaFilters,
} from "@/cloudsneeker/lib/area-findings";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import type {
  AreaFindingResource,
  AreaFindingSource,
  FindingArea,
} from "@/cloudsneeker/types/area-findings";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";

import { AreaFindingsFilters } from "./area-findings-filters";
import { AreaFindingsTable } from "./area-findings-table";
import { pagesOf } from "./area-triage-view";
import { EmptyState } from "./empty-state";
import { PageHeader } from "./page-header";
import { SectionCard } from "./section-card";

interface AreaFindingsViewProps {
  area: FindingArea;
  searchParams: SearchParamsProps;
}

const sourcesOf = (response: unknown): AreaFindingSource[] => {
  const sources = (response as { meta?: { sources?: unknown } } | undefined)
    ?.meta?.sources;
  return Array.isArray(sources) ? (sources as AreaFindingSource[]) : [];
};

const isFiltered = (filters: AreaFindingFilters): boolean =>
  filters.severities.length > 0 ||
  filters.triage !== null ||
  filters.source !== null ||
  filters.search !== "" ||
  filters.fix !== null;

/** One area's Findings page: current findings with filters and triage. */
export const AreaFindingsView = ({
  area,
  searchParams,
}: AreaFindingsViewProps) => {
  const config = AREA_CONFIG[area];
  const filters = parseAreaFilters(searchParams);

  return (
    <ContentLayout title={`${config.name} findings`} icon={<ListChecks />}>
      <PageHeader
        description={`Open findings from the latest scan of each ${config.sourceLabel.toLowerCase()}. Set a triage status on one finding or many; it follows the finding across rescans.`}
        actions={
          <Button asChild size="sm" variant="outline">
            <Link href={config.triageHref}>Triage</Link>
          </Button>
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

  return (
    <SectionCard title="Findings" description={`${total} finding(s).`}>
      <AreaFindingsFilters
        area={area}
        filters={filters}
        sources={sourcesOf(response)}
        sourceLabel={config.sourceLabel}
      />
      {findings.length === 0 ? (
        <EmptyState
          title={isFiltered(filters) ? "No findings match" : "No findings yet"}
          description={
            isFiltered(filters)
              ? "Clear a filter to see more findings."
              : config.emptyFindings
          }
          action={
            isFiltered(filters) ? (
              <Button asChild size="sm" variant="outline">
                <Link href={areaFindingsPageHref(area, {})}>Clear filters</Link>
              </Button>
            ) : undefined
          }
        />
      ) : (
        <AreaFindingsTable
          config={config}
          findings={findings}
          canTriage={canTriage}
        />
      )}
      {pages > 1 ? (
        <div className="flex items-center justify-end gap-2 text-sm">
          <span className="text-text-neutral-tertiary">
            Page {filters.page} of {pages}
          </span>
          {filters.page > 1 ? (
            <Button asChild size="xs" variant="outline">
              <Link
                href={areaFindingsPageHref(area, {
                  ...filters,
                  page: filters.page - 1,
                })}
              >
                Previous
              </Link>
            </Button>
          ) : null}
          {filters.page < pages ? (
            <Button asChild size="xs" variant="outline">
              <Link
                href={areaFindingsPageHref(area, {
                  ...filters,
                  page: filters.page + 1,
                })}
              >
                Next
              </Link>
            </Button>
          ) : null}
        </div>
      ) : null}
    </SectionCard>
  );
};
