import { Boxes, Plus } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { listAppSecApplications } from "@/cloudsneeker/actions/appsec";
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
import { RunStatusBadge } from "@/cloudsneeker/components/run-status-badge";
import { StandardFilters } from "@/cloudsneeker/components/standard/standard-filters";
import { StandardTableCard } from "@/cloudsneeker/components/standard/standard-table-card";
import {
  APPSEC_CRITICALITIES,
  APPSEC_ENVIRONMENTS,
  APPSEC_SEGMENT,
  appSecApplicationHref,
  formatAppSecDate,
} from "@/cloudsneeker/lib/appsec";
import { canManageScans } from "@/cloudsneeker/lib/appsec-server";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import {
  filterParam,
  readFilterValue,
  readPage,
  readPageSize,
  readSearch,
  STANDARD_PARAM,
} from "@/cloudsneeker/lib/standard-list";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { TABLE_FRAME_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type {
  AppSecApplicationAttributes,
  AppSecResource,
} from "@/cloudsneeker/types/appsec";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { cn } from "@/lib/utils";
import type { SearchParamsProps } from "@/types";

interface PageProps {
  searchParams: Promise<SearchParamsProps>;
}

const BASE = appSecurityHref(APPSEC_SEGMENT.APPLICATIONS);

const PAGE_SIZE = 25;

interface ApplicationListState {
  search: string;
  criticality: string;
  environment: string;
  page: number;
  pageSize: number;
}

const capitalize = (value: string): string =>
  value.charAt(0).toUpperCase() + value.slice(1);

export default async function AppSecurityApplicationsPage({
  searchParams,
}: PageProps) {
  const params = await searchParams;
  const state: ApplicationListState = {
    search: readSearch(params, ["q"]),
    criticality: readFilterValue(params, "criticality"),
    environment: readFilterValue(params, "environment"),
    page: readPage(params),
    pageSize: readPageSize(params, PAGE_SIZE),
  };
  const canManage = await canManageScans();

  return (
    <ContentLayout title="Applications" icon={<Boxes />}>
      <PageHeader
        description="An application groups the repositories, images, archives, SBOMs and clusters that belong to one product. Its criticality, environment and exposure feed the priority of its findings."
        actions={
          canManage ? (
            <Button asChild size="sm">
              <Link href={`${BASE}/new`}>
                <Plus aria-hidden="true" />
                New application
              </Link>
            </Button>
          ) : null
        }
      />
      <div className="flex flex-col gap-6">
        <StandardFilters
          testIdPrefix="applications"
          filters={[
            {
              key: "criticality",
              label: "Criticalities",
              single: true,
              options: APPSEC_CRITICALITIES.map((value) => ({
                value,
                label: capitalize(value),
              })),
            },
            {
              key: "environment",
              label: "Environments",
              single: true,
              options: APPSEC_ENVIRONMENTS.map((value) => ({
                value,
                label: capitalize(value),
              })),
            },
          ]}
        />
        <Suspense
          key={JSON.stringify(state)}
          fallback={<Skeleton className="h-64 w-full rounded-xl" />}
        >
          <SSRApplications state={state} canManage={canManage} />
        </Suspense>
      </div>
    </ContentLayout>
  );
}

const hrefFor = (state: ApplicationListState, page: number): string => {
  const query = new URLSearchParams();
  if (state.search) query.set(STANDARD_PARAM.SEARCH, state.search);
  if (state.criticality)
    query.set(filterParam("criticality"), state.criticality);
  if (state.environment)
    query.set(filterParam("environment"), state.environment);
  if (state.pageSize !== PAGE_SIZE)
    query.set(STANDARD_PARAM.PAGE_SIZE, String(state.pageSize));
  if (page > 1) query.set(STANDARD_PARAM.PAGE, String(page));
  const serialized = query.toString();
  return serialized ? `${BASE}?${serialized}` : BASE;
};

const SSRApplications = async ({
  state,
  canManage,
}: {
  state: ApplicationListState;
  canManage: boolean;
}) => {
  const { search, page } = state;
  const filtered = Boolean(
    state.search || state.criticality || state.environment,
  );
  const response = await listAppSecApplications({
    "filter[search]": search,
    ...(state.criticality ? { "filter[criticality]": state.criticality } : {}),
    ...(state.environment ? { "filter[environment]": state.environment } : {}),
    "page[number]": String(page),
    "page[size]": String(state.pageSize),
  });
  if (!isListResponse(response)) {
    return (
      <LoadError
        title="Applications"
        what="Applications"
        reloadHref={hrefFor(state, page)}
      />
    );
  }
  const applications =
    responseList<AppSecResource<AppSecApplicationAttributes>>(response);
  const total = responseCount(response) ?? applications.length;

  return (
    <StandardTableCard
      searchPlaceholder="Search name or owner (press Enter)"
      total={total}
      footer={
        <PageNav
          page={page}
          pages={pagesOf(response)}
          count={total}
          noun="applications"
          pageSize={state.pageSize}
          hrefFor={(next) => hrefFor(state, next)}
        />
      }
    >
      {applications.length === 0 ? (
        <EmptyState
          title={filtered ? "No applications match" : "No applications yet"}
          description={
            filtered
              ? "Clear a filter or try another name."
              : "Create an application and assign its assets to see posture per product instead of per scan target."
          }
          action={
            canManage && !filtered ? (
              <Button asChild size="sm">
                <Link href={`${BASE}/new`}>Create an application</Link>
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className={TABLE_FRAME_CLASS}>
          <table className={TABLE_CLASS}>
            <thead>
              <tr>
                {[
                  "Application",
                  "Top score",
                  "Context",
                  "Assets",
                  "Active findings",
                  "Critical",
                  "High",
                  "SBOM",
                  "Last scan",
                ].map((heading) => (
                  <th key={heading} scope="col" className={TH_CLASS}>
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {applications.map(({ id, attributes }) => {
                const score = attributes.risk_score ?? 0;
                const targets = attributes.targets ?? 0;
                return (
                  <tr key={id}>
                    <td className={cn(TD_PRIMARY_CLASS, "max-w-xs")}>
                      <Link
                        href={appSecApplicationHref(id)}
                        className={ROW_LINK_CLASS}
                      >
                        {attributes.name}
                      </Link>
                      <p className="text-text-neutral-tertiary truncate text-xs">
                        {attributes.owner || "No owner"}
                      </p>
                    </td>
                    <td className={TD_CLASS}>
                      {attributes.active_findings ? (
                        <span
                          className="tabular-nums"
                          title="Highest priority score among the application's active findings"
                        >
                          {score}
                        </span>
                      ) : (
                        "–"
                      )}
                    </td>
                    <td className={cn(TD_CLASS, "text-xs")}>
                      {attributes.criticality} · {attributes.environment}
                      {attributes.internet_exposed ? " · internet facing" : ""}
                    </td>
                    <td className={cn(TD_CLASS, "text-xs")}>
                      <span className="tabular-nums">{targets}</span>
                      {attributes.target_types?.length
                        ? ` (${attributes.target_types.map(labelForTrivyMode).join(", ")})`
                        : ""}
                    </td>
                    <td className={cn(TD_CLASS, "tabular-nums")}>
                      {attributes.active_findings ?? 0}
                    </td>
                    <td className={cn(TD_CLASS, "tabular-nums")}>
                      {attributes.critical ?? 0}
                    </td>
                    <td className={cn(TD_CLASS, "tabular-nums")}>
                      {attributes.high ?? 0}
                    </td>
                    <td className={cn(TD_CLASS, "text-xs tabular-nums")}>
                      {targets
                        ? `${attributes.sbom_targets ?? 0} of ${targets}`
                        : "–"}
                    </td>
                    <td className={cn(TD_CLASS, "text-xs whitespace-nowrap")}>
                      {attributes.last_scan_at ? (
                        <span className="flex flex-col items-start gap-1">
                          {formatAppSecDate(attributes.last_scan_at)}
                          <RunStatusBadge
                            status={attributes.last_scan_status ?? ""}
                          />
                        </span>
                      ) : (
                        "Never"
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </StandardTableCard>
  );
};
