import { Archive, Filter, Radar } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { listTrivyRuns } from "@/cloudsneeker/actions/trivy";
import { BRAND } from "@/cloudsneeker/brand";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import {
  RunStatusBadge,
  runStatusLabel,
} from "@/cloudsneeker/components/run-status-badge";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  type Application,
  applicationHref,
  applicationsHref,
  groupTargetsIntoApplications,
} from "@/cloudsneeker/lib/app-security-applications";
import { loadAllTargets } from "@/cloudsneeker/lib/app-security-applications-data";
import {
  APP_SECURITY_TAB,
  appSecurityTabHref,
} from "@/cloudsneeker/lib/app-security-dashboard";
import { responsePages } from "@/cloudsneeker/lib/app-security-scan-history";
import {
  archivedScansHref,
  errorSnippet,
  formatDuration,
  formatRunTime,
  parseScanFilters,
  runDurationMs,
  runFindingCount,
  SCAN_FILTER_PARAM,
  SCAN_STATUSES,
  SCAN_TRIGGER_LABEL,
  SCAN_TRIGGERS,
  SCAN_TYPE_LABEL,
  SCAN_TYPES,
  type ScanFilters,
  scanRunsQuery,
  scansHref,
  scanTriggerLabel,
  scanTypeLabel,
} from "@/cloudsneeker/lib/app-security-scans";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import {
  FORM_SELECT_CLASS,
  TABLE_BODY_CLASS,
  TABLE_CLASS,
  TABLE_FRAME_CLASS,
  TABLE_HEAD_CLASS,
  TABLE_HEADER_CELL_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type {
  TrivyRunResource,
  TrivyRunStatus,
} from "@/cloudsneeker/types/trivy";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { cn } from "@/lib/utils";
import type { SearchParamsProps } from "@/types";

interface ScanningCentrePageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function ScanningCentrePage({
  searchParams,
}: ScanningCentrePageProps) {
  const filters = parseScanFilters(await searchParams);

  return (
    <ContentLayout
      title={`${BRAND.appSecurityName} · Security scanning`}
      icon={<Radar />}
    >
      <PageHeader
        description="Every scan across your applications, newest first. Filter by status, scan type, trigger or application, and open a scan for its results."
        actions={
          <>
            <Button asChild size="sm" variant="outline">
              <Link href={applicationsHref()}>Applications</Link>
            </Button>
            <Button asChild size="sm" variant="outline">
              <Link href={archivedScansHref()}>
                <Archive aria-hidden="true" />
                Archived scans
              </Link>
            </Button>
          </>
        }
      />
      <Suspense fallback={<Skeleton className="h-96 w-full rounded-xl" />}>
        <SSRScanningCentre filters={filters} />
      </Suspense>
    </ContentLayout>
  );
}

const chipClass = (active: boolean) =>
  cn(
    "rounded-full border px-3 py-1 text-xs font-medium transition-colors",
    active
      ? "border-button-primary bg-button-primary text-black"
      : "border-border-neutral-secondary text-text-neutral-secondary hover:text-text-neutral-primary",
  );

/** Scans per status under the other filters; null counts when one fails. */
const loadStatusCounts = async (
  filters: ScanFilters,
): Promise<Record<TrivyRunStatus, number | null>> => {
  const counts = await Promise.all(
    SCAN_STATUSES.map(async (status) => {
      const response: unknown = await listTrivyRuns(
        scanRunsQuery({ ...filters, status, page: 1 }, 1),
      );
      return [status, responseCount(response)] as const;
    }),
  );
  return Object.fromEntries(counts) as Record<TrivyRunStatus, number | null>;
};

const StatusChips = ({
  filters,
  counts,
}: {
  filters: ScanFilters;
  counts: Record<TrivyRunStatus, number | null>;
}) => (
  <nav aria-label="Scan status" className="flex flex-wrap gap-2">
    <Link
      href={scansHref(filters, { status: undefined })}
      aria-current={filters.status ? undefined : "page"}
      className={chipClass(!filters.status)}
    >
      All statuses
    </Link>
    {SCAN_STATUSES.map((status) => {
      const count = counts[status];
      return (
        <Link
          key={status}
          href={scansHref(filters, { status })}
          aria-current={filters.status === status ? "page" : undefined}
          className={chipClass(filters.status === status)}
        >
          {count === null
            ? runStatusLabel(status)
            : `${runStatusLabel(status)} (${count})`}
        </Link>
      );
    })}
  </nav>
);

const FilterForm = ({
  filters,
  applications,
}: {
  filters: ScanFilters;
  applications: Application[];
}) => (
  <form
    method="get"
    action={scansHref()}
    className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-[repeat(4,minmax(0,1fr))_auto] lg:items-end"
  >
    <label className="flex min-w-0 flex-col gap-1 text-sm">
      <span className="text-text-neutral-secondary text-xs font-medium">
        Status
      </span>
      <select
        name={SCAN_FILTER_PARAM.STATUS}
        defaultValue={filters.status ?? ""}
        className={FORM_SELECT_CLASS}
      >
        <option value="">All statuses</option>
        {SCAN_STATUSES.map((status) => (
          <option key={status} value={status}>
            {runStatusLabel(status)}
          </option>
        ))}
      </select>
    </label>
    <label className="flex min-w-0 flex-col gap-1 text-sm">
      <span className="text-text-neutral-secondary text-xs font-medium">
        Scan type
      </span>
      <select
        name={SCAN_FILTER_PARAM.TYPE}
        defaultValue={filters.mode ?? ""}
        className={FORM_SELECT_CLASS}
      >
        <option value="">All scan types</option>
        {SCAN_TYPES.map((mode) => (
          <option key={mode} value={mode}>
            {SCAN_TYPE_LABEL[mode]}
          </option>
        ))}
      </select>
    </label>
    <label className="flex min-w-0 flex-col gap-1 text-sm">
      <span className="text-text-neutral-secondary text-xs font-medium">
        Trigger
      </span>
      <select
        name={SCAN_FILTER_PARAM.TRIGGER}
        defaultValue={filters.trigger ?? ""}
        className={FORM_SELECT_CLASS}
      >
        <option value="">Manual and scheduled</option>
        {SCAN_TRIGGERS.map((trigger) => (
          <option key={trigger} value={trigger}>
            {SCAN_TRIGGER_LABEL[trigger]}
          </option>
        ))}
      </select>
    </label>
    <label className="flex min-w-0 flex-col gap-1 text-sm">
      <span className="text-text-neutral-secondary text-xs font-medium">
        Application
      </span>
      <select
        name={SCAN_FILTER_PARAM.APPLICATION}
        defaultValue={filters.application ?? ""}
        className={FORM_SELECT_CLASS}
      >
        <option value="">All applications</option>
        {applications.map((application) => (
          <option key={application.id} value={application.id}>
            {application.name}
          </option>
        ))}
      </select>
    </label>
    <div className="flex gap-2">
      <Button type="submit" size="sm" variant="outline" className="h-10">
        <Filter aria-hidden="true" />
        Apply
      </Button>
      <Button asChild size="sm" variant="ghost" className="h-10">
        <Link href={scansHref()}>Clear</Link>
      </Button>
    </div>
  </form>
);

const HEADERS = [
  "Target",
  "Application",
  "Scan type",
  "Trigger",
  "Status",
  "Started",
  "Finished",
  "Duration",
  "Findings",
  "Error",
] as const;

const ScanTable = ({
  runs,
  applicationNames,
}: {
  runs: TrivyRunResource[];
  applicationNames: Map<string, string>;
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
        {runs.map((run) => {
          const attributes = run.attributes;
          const applicationName =
            applicationNames.get(attributes.provider_id) ||
            attributes.provider_uid ||
            "";
          const findings = runFindingCount(run);
          const error = errorSnippet(attributes.error);
          return (
            <tr key={run.id}>
              <td className="max-w-56 px-3 py-2">
                <Link
                  href={appSecurityHref(attributes.target_id, "runs", run.id)}
                  className="text-text-neutral-primary rounded-sm font-medium break-words underline-offset-2 hover:underline"
                >
                  {attributes.target_name || attributes.target_id}
                </Link>
              </td>
              <td className="text-text-neutral-secondary max-w-56 px-3 py-2 break-words">
                {applicationName && attributes.provider_id ? (
                  <Link
                    href={applicationHref(attributes.provider_id)}
                    className="underline-offset-2 hover:underline"
                  >
                    {applicationName}
                  </Link>
                ) : (
                  "—"
                )}
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 whitespace-nowrap">
                {scanTypeLabel(
                  attributes.target_mode || attributes.summary?.mode,
                )}
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 whitespace-nowrap">
                {scanTriggerLabel(attributes.trigger)}
              </td>
              <td className="px-3 py-2">
                <RunStatusBadge status={attributes.status} />
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 text-xs whitespace-nowrap">
                {formatRunTime(attributes.started_at)}
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 text-xs whitespace-nowrap">
                {formatRunTime(attributes.finished_at)}
              </td>
              <td className="text-text-neutral-secondary px-3 py-2 whitespace-nowrap tabular-nums">
                {formatDuration(runDurationMs(run))}
              </td>
              <td className="px-3 py-2 tabular-nums">
                {findings === null ? "—" : findings}
              </td>
              <td className="text-text-error-primary max-w-64 px-3 py-2 text-xs break-words">
                {error ? <span title={attributes.error}>{error}</span> : null}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);

const Pagination = ({
  filters,
  pages,
}: {
  filters: ScanFilters;
  pages: number;
}) =>
  pages > 1 ? (
    <nav
      aria-label="Scan pages"
      className="flex items-center justify-between gap-2"
    >
      {filters.page > 1 ? (
        <Button asChild variant="outline" size="sm">
          <Link href={scansHref(filters, { page: filters.page - 1 })}>
            Previous
          </Link>
        </Button>
      ) : (
        <span />
      )}
      <span className="text-text-neutral-secondary text-sm">
        {`Page ${filters.page} of ${pages}`}
      </span>
      {filters.page < pages ? (
        <Button asChild variant="outline" size="sm">
          <Link href={scansHref(filters, { page: filters.page + 1 })}>
            Next
          </Link>
        </Button>
      ) : (
        <span />
      )}
    </nav>
  ) : null;

const SSRScanningCentre = async ({ filters }: { filters: ScanFilters }) => {
  const [runsResponse, statusCounts, loadedTargets] = await Promise.all([
    listTrivyRuns(scanRunsQuery(filters)),
    loadStatusCounts(filters),
    loadAllTargets(),
  ]);
  const applications = groupTargetsIntoApplications(
    loadedTargets?.targets ?? [],
  ).sort((a, b) => a.name.localeCompare(b.name));
  const applicationNames = new Map(
    applications.map((application) => [application.id, application.name]),
  );
  const runsLoaded = isListResponse(runsResponse);
  const runs = responseList<TrivyRunResource>(runsResponse);
  const total = responseCount(runsResponse);
  const filtered = Boolean(
    filters.status || filters.mode || filters.trigger || filters.application,
  );

  return (
    <SectionCard
      title="Scans"
      description={
        total === null
          ? "Current scans, newest first. Scans older than one year move to the archive."
          : `${total} ${filtered ? "matching" : "current"} scans, newest first. Scans older than one year move to the archive.`
      }
    >
      <StatusChips filters={filters} counts={statusCounts} />
      <FilterForm filters={filters} applications={applications} />
      {!runsLoaded ? (
        <EmptyState
          title="Scans could not be loaded"
          description="The service did not answer. Reload the page in a moment."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={scansHref(filters, { page: filters.page })}>
                Reload
              </Link>
            </Button>
          }
        />
      ) : runs.length === 0 ? (
        <EmptyState
          icon={<Radar />}
          title={filtered ? "No scans match these filters" : "No scans yet"}
          description={
            filtered
              ? "Clear a filter to see more scans."
              : "Open a target and start a scan, or turn on a schedule."
          }
          action={
            <Button asChild size="sm" variant="outline">
              <Link
                href={
                  filtered
                    ? scansHref()
                    : appSecurityTabHref(APP_SECURITY_TAB.TARGETS)
                }
              >
                {filtered ? "Clear filters" : "Go to targets"}
              </Link>
            </Button>
          }
        />
      ) : (
        <ScanTable runs={runs} applicationNames={applicationNames} />
      )}
      {runsLoaded ? (
        <Pagination filters={filters} pages={responsePages(runsResponse)} />
      ) : null}
    </SectionCard>
  );
};
