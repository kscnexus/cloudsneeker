import { Package } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import {
  getAppSecComponentsSummary,
  listAppSecComponents,
} from "@/cloudsneeker/actions/appsec";
import {
  AppSecComponentsTable,
  ComponentFiltersBar,
  type ComponentFilters,
  componentsHref,
  componentsQuery,
  parseComponentFilters,
} from "@/cloudsneeker/components/appsec-components-table";
import {
  CountBars,
  LoadError,
  Pager,
} from "@/cloudsneeker/components/appsec-ui";
import { pagesOf } from "@/cloudsneeker/components/area-triage-view";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { StatTile } from "@/cloudsneeker/components/stat-tile";
import { APPSEC_SEGMENT, attributesOf } from "@/cloudsneeker/lib/appsec";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type {
  AppSecComponentAttributes,
  AppSecResource,
  AppSecSbomSummary,
} from "@/cloudsneeker/types/appsec";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";

interface PageProps {
  searchParams: Promise<SearchParamsProps>;
}

const BASE = appSecurityHref(APPSEC_SEGMENT.COMPONENTS);

const one = (value: string | string[] | undefined): string =>
  ((Array.isArray(value) ? value[0] : value) ?? "").trim();

export default async function AppSecurityComponentsPage({
  searchParams,
}: PageProps) {
  const params = await searchParams;
  const filters = parseComponentFilters(params);
  const scope: Record<string, string> = {};
  if (one(params.target)) scope.target = one(params.target);
  if (one(params.application)) scope.application = one(params.application);

  return (
    <ContentLayout title="Software composition" icon={<Package />}>
      <PageHeader
        description="Every package in the newest inventory of each asset: versions, direct or transitive, licenses, known vulnerabilities and the version that fixes them."
        actions={
          <Button asChild size="sm" variant="outline">
            <Link href={appSecurityHref(APPSEC_SEGMENT.SBOMS)}>SBOMs</Link>
          </Button>
        }
      />
      <Suspense
        key={JSON.stringify([filters, scope])}
        fallback={<Skeleton className="h-96 w-full rounded-xl" />}
      >
        <SSRComponents filters={filters} scope={scope} />
      </Suspense>
    </ContentLayout>
  );
}

const SSRComponents = async ({
  filters,
  scope,
}: {
  filters: ComponentFilters;
  scope: Record<string, string>;
}) => {
  const scopeQuery: Record<string, string> = {};
  if (scope.target) scopeQuery["filter[target]"] = scope.target;
  if (scope.application) scopeQuery["filter[application]"] = scope.application;
  const [response, summaryResponse] = await Promise.all([
    listAppSecComponents({ ...componentsQuery(filters), ...scopeQuery }),
    getAppSecComponentsSummary(scopeQuery),
  ]);
  if (!isListResponse(response)) {
    return (
      <LoadError
        title="Components"
        what="Components"
        reloadHref={componentsHref(BASE, filters, scope)}
      />
    );
  }
  const components =
    responseList<AppSecResource<AppSecComponentAttributes>>(response);
  const total = responseCount(response) ?? components.length;
  const summary = attributesOf<AppSecSbomSummary>(summaryResponse);
  const ecosystems = Object.keys(summary?.ecosystems ?? {});
  const hasFilters =
    filters.search !== "" ||
    filters.ecosystem !== "" ||
    filters.relationship !== "" ||
    filters.vulnerable ||
    filters.unlicensed ||
    filters.license !== "";

  return (
    <div className="flex flex-col gap-6">
      {summary && (summary.total ?? 0) > 0 ? (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
            <StatTile label="Components" value={summary.total ?? 0} />
            <StatTile
              label="Distinct packages"
              value={summary.distinct_packages ?? 0}
            />
            <StatTile
              label="Vulnerable"
              value={summary.vulnerable ?? 0}
              tone="high"
              href={componentsHref(BASE, { vulnerable: true }, scope)}
            />
            <StatTile
              label="Direct"
              value={summary.relationships?.direct ?? 0}
              hint={`${summary.relationships?.indirect ?? 0} transitive`}
              href={componentsHref(BASE, { relationship: "direct" }, scope)}
            />
            <StatTile
              label="No license stated"
              value={summary.without_license ?? 0}
              tone="warning"
              href={componentsHref(BASE, { unlicensed: true }, scope)}
            />
          </div>
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            <SectionCard title="Ecosystems">
              <CountBars
                items={Object.entries(summary.ecosystems ?? {})
                  .slice(0, 10)
                  .map(([ecosystem, count]) => ({
                    key: ecosystem,
                    label: ecosystem || "unknown",
                    count,
                    href: componentsHref(BASE, { ecosystem }, scope),
                  }))}
              />
            </SectionCard>
            <SectionCard
              title="Licenses"
              description="As declared by the packages. Classification and policy are under License compliance."
            >
              <CountBars
                items={Object.entries(summary.licenses ?? {})
                  .slice(0, 10)
                  .map(([license, count]) => ({
                    key: license,
                    label: license,
                    count,
                    href: componentsHref(BASE, { license }, scope),
                  }))}
              />
            </SectionCard>
          </div>
        </>
      ) : null}
      <SectionCard title="Components" description={`${total} component(s).`}>
        <ComponentFiltersBar
          base={BASE}
          filters={filters}
          ecosystems={ecosystems}
          extra={scope}
        />
        {components.length === 0 ? (
          <EmptyState
            title={hasFilters ? "No components match" : "No inventory yet"}
            description={
              hasFilters
                ? "Clear a filter to see more components."
                : "An inventory is stored when a scan lists packages. Scan a repository, image, archive or SBOM."
            }
          />
        ) : (
          <AppSecComponentsTable components={components} showTarget />
        )}
        <Pager
          page={filters.page}
          pages={pagesOf(response)}
          hrefFor={(page) => componentsHref(BASE, { ...filters, page }, scope)}
        />
      </SectionCard>
    </div>
  );
};
