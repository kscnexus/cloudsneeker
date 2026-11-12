import { FileStack } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import {
  listAppSecApplications,
  listAppSecSboms,
} from "@/cloudsneeker/actions/appsec";
import {
  LoadError,
  ROW_LINK_CLASS,
  TABLE_CLASS,
  TD_CLASS,
  TD_PRIMARY_CLASS,
  TH_CLASS,
} from "@/cloudsneeker/components/appsec-ui";
import { pagesOf } from "@/cloudsneeker/components/area-triage-view";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { PageNav } from "@/cloudsneeker/components/page-nav";
import { StandardFilters } from "@/cloudsneeker/components/standard/standard-filters";
import { StandardTableCard } from "@/cloudsneeker/components/standard/standard-table-card";
import {
  APPSEC_SEGMENT,
  appSecSbomHref,
  formatAppSecDate,
} from "@/cloudsneeker/lib/appsec";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import {
  filterParam,
  readFilterValue,
  readPage,
  STANDARD_PARAM,
} from "@/cloudsneeker/lib/standard-list";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { TABLE_FRAME_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type {
  AppSecResource,
  AppSecSbomAttributes,
} from "@/cloudsneeker/types/appsec";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { cn } from "@/lib/utils";
import type { SearchParamsProps } from "@/types";

interface PageProps {
  searchParams: Promise<SearchParamsProps>;
}

interface SbomListFilters {
  history: boolean;
  target: string;
  application: string;
  page: number;
}

const BASE = appSecurityHref(APPSEC_SEGMENT.SBOMS);

const one = (value: string | string[] | undefined): string =>
  ((Array.isArray(value) ? value[0] : value) ?? "").trim();

const VERSIONS_ALL = "all";

const hrefFor = (filters: Partial<SbomListFilters>): string => {
  const query = new URLSearchParams();
  if (filters.history && !filters.target)
    query.set(filterParam("versions"), VERSIONS_ALL);
  if (filters.target) query.set("target", filters.target);
  if (filters.application)
    query.set(filterParam("application"), filters.application);
  if (filters.page && filters.page > 1)
    query.set(STANDARD_PARAM.PAGE, String(filters.page));
  const serialized = query.toString();
  return serialized ? `${BASE}?${serialized}` : BASE;
};

export default async function AppSecuritySbomsPage({
  searchParams,
}: PageProps) {
  const params = await searchParams;
  const target = one(params.target);
  const filters: SbomListFilters = {
    history:
      readFilterValue(params, "versions") === VERSIONS_ALL ||
      one(params.history) === "1" ||
      target !== "",
    target,
    application: readFilterValue(params, "application", ["application"]),
    page: readPage(params),
  };
  const applications = await listAppSecApplications({
    "page[size]": "100",
    sort: "name",
  });
  const applicationOptions = isListResponse(applications)
    ? responseList<AppSecResource<{ name?: string }>>(applications).map(
        (item) => ({ value: item.id, label: item.attributes.name || item.id }),
      )
    : [];
  return (
    <ContentLayout title="SBOMs" icon={<FileStack />}>
      <PageHeader
        description="A software bill of materials is stored for every completed scan that lists packages, and for every imported SBOM document. Open one to browse its components, download it, or compare it with an earlier version."
        actions={
          <Button asChild size="sm">
            <Link href={`${appSecurityHref("new")}?mode=sbom`}>
              Import an SBOM
            </Link>
          </Button>
        }
      />
      <div className="flex flex-col gap-6">
        <StandardFilters
          testIdPrefix="sboms"
          filters={[
            {
              key: "versions",
              label: "Versions (newest per asset)",
              single: true,
              options: [{ value: VERSIONS_ALL, label: "All versions" }],
            },
            {
              key: "application",
              label: "Applications",
              single: true,
              wide: true,
              options: applicationOptions,
            },
          ]}
        />
        {filters.target ? (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-text-neutral-secondary">Scoped to</span>
            <Link
              href={hrefFor({ application: filters.application })}
              className="border-border-neutral-secondary text-text-neutral-primary hover:bg-bg-neutral-tertiary rounded-full border px-2.5 py-1"
            >
              One asset ×
            </Link>
          </div>
        ) : null}
        <Suspense
          key={JSON.stringify(filters)}
          fallback={<Skeleton className="h-64 w-full rounded-xl" />}
        >
          <SSRSboms filters={filters} />
        </Suspense>
      </div>
    </ContentLayout>
  );
}

const SSRSboms = async ({ filters }: { filters: SbomListFilters }) => {
  const response = await listAppSecSboms({
    "filter[latest]": filters.history ? undefined : "true",
    "filter[target]": filters.target || undefined,
    "filter[application]": filters.application || undefined,
    "page[number]": String(filters.page),
    "page[size]": "25",
  });
  if (!isListResponse(response)) {
    return (
      <LoadError title="SBOMs" what="SBOMs" reloadHref={hrefFor(filters)} />
    );
  }
  const sboms = responseList<AppSecResource<AppSecSbomAttributes>>(response);
  const total = responseCount(response) ?? sboms.length;

  return (
    <StandardTableCard
      total={total}
      footer={
        <PageNav
          page={filters.page}
          pages={pagesOf(response)}
          count={total}
          noun={filters.history ? "inventory versions" : "assets"}
          hrefFor={(page) => hrefFor({ ...filters, page })}
        />
      }
    >
      {sboms.length === 0 ? (
        <EmptyState
          title="No SBOMs yet"
          description="Scan a repository, image or archive, or import a CycloneDX or SPDX document."
        />
      ) : (
        <div className={TABLE_FRAME_CLASS}>
          <table className={TABLE_CLASS}>
            <thead>
              <tr>
                {[
                  "Asset",
                  "Version",
                  "Source",
                  "Created",
                  "Components",
                  "Vulnerable",
                  "Vulnerabilities",
                  "Top licenses",
                ].map((heading) => (
                  <th key={heading} scope="col" className={TH_CLASS}>
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sboms.map(({ id, attributes }) => (
                <tr key={id}>
                  <td className={cn(TD_PRIMARY_CLASS, "max-w-xs")}>
                    <Link href={appSecSbomHref(id)} className={ROW_LINK_CLASS}>
                      {attributes.target_name}
                    </Link>
                    <p className="text-text-neutral-tertiary truncate text-xs">
                      {attributes.application_name
                        ? `${attributes.application_name} · `
                        : ""}
                      {labelForTrivyMode(attributes.target_type)}
                    </p>
                  </td>
                  <td className={cn(TD_CLASS, "tabular-nums")}>
                    <Link
                      className="underline"
                      href={hrefFor({ target: attributes.target_id })}
                    >
                      v{attributes.version}
                    </Link>
                  </td>
                  <td className={TD_CLASS}>
                    {attributes.source === "imported"
                      ? `Imported${attributes.document_format ? ` (${attributes.document_format})` : ""}`
                      : "Scan"}
                  </td>
                  <td className={cn(TD_CLASS, "text-xs whitespace-nowrap")}>
                    {formatAppSecDate(attributes.inserted_at)}
                  </td>
                  <td className={cn(TD_CLASS, "tabular-nums")}>
                    {attributes.component_count}
                  </td>
                  <td className={cn(TD_CLASS, "tabular-nums")}>
                    {attributes.vulnerable_component_count}
                  </td>
                  <td className={cn(TD_CLASS, "tabular-nums")}>
                    {attributes.vulnerability_count}
                  </td>
                  <td className={cn(TD_CLASS, "max-w-48 text-xs")}>
                    {Object.keys(attributes.summary.licenses ?? {})
                      .slice(0, 3)
                      .join(", ") || "None stated"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </StandardTableCard>
  );
};
