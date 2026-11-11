import { Boxes, Plus } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { listAppSecApplications } from "@/cloudsneeker/actions/appsec";
import {
  LoadError,
  Pager,
  ROW_LINK_CLASS,
  TABLE_CLASS,
  TABLE_WRAPPER_CLASS,
  TD_CLASS,
  TD_PRIMARY_CLASS,
  TH_CLASS,
} from "@/cloudsneeker/components/appsec-ui";
import { pagesOf } from "@/cloudsneeker/components/area-triage-view";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { RunStatusBadge } from "@/cloudsneeker/components/run-status-badge";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
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
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type {
  AppSecApplicationAttributes,
  AppSecResource,
} from "@/cloudsneeker/types/appsec";
import { Button, Input, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { cn } from "@/lib/utils";
import type { SearchParamsProps } from "@/types";

interface PageProps {
  searchParams: Promise<SearchParamsProps>;
}

const BASE = appSecurityHref(APPSEC_SEGMENT.APPLICATIONS);

const one = (value: string | string[] | undefined): string =>
  (Array.isArray(value) ? value[0] : value) ?? "";

export default async function AppSecurityApplicationsPage({
  searchParams,
}: PageProps) {
  const params = await searchParams;
  const search = one(params.q).trim();
  const page = Math.max(1, Number.parseInt(one(params.page), 10) || 1);
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
      <Suspense
        key={`${search}-${page}`}
        fallback={<Skeleton className="h-64 w-full rounded-xl" />}
      >
        <SSRApplications search={search} page={page} canManage={canManage} />
      </Suspense>
    </ContentLayout>
  );
}

const hrefFor = (search: string, page: number): string => {
  const query = new URLSearchParams();
  if (search) query.set("q", search);
  if (page > 1) query.set("page", String(page));
  const serialized = query.toString();
  return serialized ? `${BASE}?${serialized}` : BASE;
};

const SSRApplications = async ({
  search,
  page,
  canManage,
}: {
  search: string;
  page: number;
  canManage: boolean;
}) => {
  const response = await listAppSecApplications({
    "filter[search]": search,
    "page[number]": String(page),
    "page[size]": "25",
  });
  if (!isListResponse(response)) {
    return (
      <LoadError
        title="Applications"
        what="Applications"
        reloadHref={hrefFor(search, page)}
      />
    );
  }
  const applications =
    responseList<AppSecResource<AppSecApplicationAttributes>>(response);
  const total = responseCount(response) ?? applications.length;

  return (
    <SectionCard title="Inventory" description={`${total} application(s).`}>
      <form method="get" className="flex flex-wrap items-end gap-2">
        <label className="flex min-w-48 flex-1 flex-col gap-1 text-xs">
          <span className="text-text-neutral-secondary font-semibold">
            Search
          </span>
          <Input name="q" defaultValue={search} placeholder="Name or owner" />
        </label>
        <Button type="submit" size="sm">
          Apply
        </Button>
      </form>
      {applications.length === 0 ? (
        <EmptyState
          title={search ? "No applications match" : "No applications yet"}
          description={
            search
              ? "Try another name."
              : "Create an application and assign its assets to see posture per product instead of per scan target."
          }
          action={
            canManage && !search ? (
              <Button asChild size="sm">
                <Link href={`${BASE}/new`}>Create an application</Link>
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className={TABLE_WRAPPER_CLASS}>
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
      <Pager
        page={page}
        pages={pagesOf(response)}
        hrefFor={(next) => hrefFor(search, next)}
      />
    </SectionCard>
  );
};
