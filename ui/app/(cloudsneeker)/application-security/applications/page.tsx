import { AppWindow, Plus, Search } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { BRAND } from "@/cloudsneeker/brand";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  type Application,
  APPLICATION_SORT_LABEL,
  APPLICATION_SORTS,
  applicationHref,
  applicationPostureLabel,
  APPLICATIONS_PAGE_SIZE,
  APPLICATIONS_PARAM,
  type ApplicationsQuery,
  applicationsHref,
  attachSummaries,
  groupTargetsIntoApplications,
  paginate,
  parseApplicationsQuery,
  scanTypeLabels,
  searchApplications,
  sortApplications,
} from "@/cloudsneeker/lib/app-security-applications";
import {
  loadAllTargets,
  loadApplicationSummaries,
} from "@/cloudsneeker/lib/app-security-applications-data";
import { newTargetHref } from "@/cloudsneeker/lib/app-security-dashboard";
import { applicationFindingsHref } from "@/cloudsneeker/lib/app-security-scans";
import {
  FORM_SELECT_CLASS,
  TABLE_BODY_CLASS,
  TABLE_CLASS,
  TABLE_FRAME_CLASS,
  TABLE_HEAD_CLASS,
  TABLE_HEADER_CELL_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";

interface ApplicationInventoryPageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function ApplicationInventoryPage({
  searchParams,
}: ApplicationInventoryPageProps) {
  const query = parseApplicationsQuery(await searchParams);

  return (
    <ContentLayout
      title={`${BRAND.appSecurityName} · Applications`}
      icon={<AppWindow />}
    >
      <PageHeader
        description="Every repository and source you scan, with its open findings and risk posture. Open an application for its targets, findings and scans."
        actions={
          <>
            <Button asChild size="sm" variant="outline">
              <Link href={appSecurityHref()}>Dashboard</Link>
            </Button>
            <Button asChild size="sm">
              <Link href={newTargetHref()}>
                <Plus aria-hidden="true" />
                Add repository
              </Link>
            </Button>
          </>
        }
      />
      <Suspense fallback={<Skeleton className="h-96 w-full rounded-xl" />}>
        <SSRApplicationInventory query={query} />
      </Suspense>
    </ContentLayout>
  );
}

const HEADERS = [
  "Application",
  "Repository",
  "Scan types",
  "Targets",
  "Open findings",
  "Critical",
  "High",
  "Posture",
] as const;

const countCell = (value: number | undefined) =>
  typeof value === "number" ? value : "—";

const ApplicationTable = ({
  applications,
}: {
  applications: Application[];
}) => (
  <div className={TABLE_FRAME_CLASS}>
    <table className={TABLE_CLASS}>
      <thead className={TABLE_HEAD_CLASS}>
        <tr>
          {HEADERS.map((header) => (
            <th key={header} scope="col" className={TABLE_HEADER_CELL_CLASS}>
              {header}
            </th>
          ))}
        </tr>
      </thead>
      <tbody className={TABLE_BODY_CLASS}>
        {applications.map((application) => (
          <tr key={application.id}>
            <td className="max-w-64 px-3 py-2">
              <Link
                href={applicationHref(application.id)}
                className="text-text-neutral-primary rounded-sm font-medium break-words underline-offset-2 hover:underline"
              >
                {application.name}
              </Link>
            </td>
            <td className="text-text-neutral-secondary max-w-72 px-3 py-2 text-xs break-all">
              {application.repository || "—"}
            </td>
            <td className="text-text-neutral-secondary px-3 py-2 text-xs">
              {scanTypeLabels(application).join(", ") || "—"}
            </td>
            <td className="px-3 py-2 tabular-nums">
              {application.targets.length}
            </td>
            <td className="px-3 py-2 tabular-nums">
              {application.summary ? (
                <Link
                  href={applicationFindingsHref(application.id)}
                  className="underline-offset-2 hover:underline"
                >
                  {application.summary.total}
                </Link>
              ) : (
                "—"
              )}
            </td>
            <td className="px-3 py-2 tabular-nums">
              {countCell(application.summary?.critical)}
            </td>
            <td className="px-3 py-2 tabular-nums">
              {countCell(application.summary?.high)}
            </td>
            <td className="text-text-neutral-secondary px-3 py-2 whitespace-nowrap">
              {applicationPostureLabel(application)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

const SearchForm = ({ query }: { query: ApplicationsQuery }) => (
  <form
    method="get"
    action={applicationsHref()}
    role="search"
    className="flex flex-col gap-2 sm:flex-row sm:items-end"
  >
    <label className="flex min-w-0 flex-1 flex-col gap-1 text-sm">
      <span className="text-text-neutral-secondary text-xs font-medium">
        Search
      </span>
      <input
        type="search"
        name={APPLICATIONS_PARAM.QUERY}
        defaultValue={query.q ?? ""}
        placeholder="Application or repository"
        className={FORM_SELECT_CLASS}
      />
    </label>
    <label className="flex flex-col gap-1 text-sm sm:w-48">
      <span className="text-text-neutral-secondary text-xs font-medium">
        Sort by
      </span>
      <select
        name={APPLICATIONS_PARAM.SORT}
        defaultValue={query.sort}
        className={FORM_SELECT_CLASS}
      >
        {APPLICATION_SORTS.map((sort) => (
          <option key={sort} value={sort}>
            {APPLICATION_SORT_LABEL[sort]}
          </option>
        ))}
      </select>
    </label>
    <Button type="submit" size="sm" variant="outline" className="h-10">
      <Search aria-hidden="true" />
      Apply
    </Button>
  </form>
);

const Pagination = ({
  query,
  page,
  pages,
}: {
  query: ApplicationsQuery;
  page: number;
  pages: number;
}) =>
  pages > 1 ? (
    <nav
      aria-label="Application pages"
      className="flex items-center justify-between gap-2"
    >
      {page > 1 ? (
        <Button asChild variant="outline" size="sm">
          <Link href={applicationsHref({ ...query, page: page - 1 })}>
            Previous
          </Link>
        </Button>
      ) : (
        <span />
      )}
      <span className="text-text-neutral-secondary text-sm">
        {`Page ${page} of ${pages}`}
      </span>
      {page < pages ? (
        <Button asChild variant="outline" size="sm">
          <Link href={applicationsHref({ ...query, page: page + 1 })}>
            Next
          </Link>
        </Button>
      ) : (
        <span />
      )}
    </nav>
  ) : null;

const SSRApplicationInventory = async ({
  query,
}: {
  query: ApplicationsQuery;
}) => {
  const [loaded, summaries] = await Promise.all([
    loadAllTargets(),
    loadApplicationSummaries(),
  ]);

  if (!loaded) {
    // A failed request must not read as "no applications yet".
    return (
      <SectionCard title="Applications">
        <EmptyState
          title="Applications could not be loaded"
          description="The service did not answer. Reload the page in a moment."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={applicationsHref(query)}>Reload</Link>
            </Button>
          }
        />
      </SectionCard>
    );
  }

  const applications = attachSummaries(
    groupTargetsIntoApplications(loaded.targets),
    summaries ?? [],
  );

  if (applications.length === 0) {
    return (
      <SectionCard title="Applications">
        <EmptyState
          icon={<AppWindow />}
          title="No applications yet"
          description="Connect a code repository, then create a scan target for it. Each repository with a target shows up here with its findings."
          action={
            <Button asChild size="sm">
              <Link href={appSecurityHref("new")}>Add a repository</Link>
            </Button>
          }
        />
      </SectionCard>
    );
  }

  const matching = sortApplications(
    searchApplications(applications, query.q),
    query.sort,
  );
  const slice = paginate(matching, query.page, APPLICATIONS_PAGE_SIZE);

  return (
    <SectionCard
      title="Applications"
      description={
        query.q
          ? `${slice.total} of ${applications.length} applications match "${query.q}".`
          : `${applications.length} applications. Highest risk first unless you pick another order.`
      }
    >
      <SearchForm query={query} />
      {summaries === null ? (
        <p className="text-text-error-primary text-sm">
          Finding counts could not be loaded. Reload the page in a moment.
        </p>
      ) : null}
      {slice.items.length > 0 ? (
        <ApplicationTable applications={slice.items} />
      ) : (
        <EmptyState
          title="No matching applications"
          description="Try another name or repository, or clear the search."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={applicationsHref({ sort: query.sort })}>
                Clear search
              </Link>
            </Button>
          }
        />
      )}
      <Pagination query={query} page={slice.page} pages={slice.pages} />
      {loaded.truncated ? (
        <p className="text-text-neutral-tertiary text-xs">
          Showing applications from the first 2,000 targets only.
        </p>
      ) : null}
    </SectionCard>
  );
};
