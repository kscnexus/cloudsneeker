import { Download, ShieldAlert, X } from "lucide-react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Suspense } from "react";

import {
  getAppSecFindingsSummary,
  listAppSecApplications,
  listAppSecFindings,
} from "@/cloudsneeker/actions/appsec";
import { newAlertHref } from "@/cloudsneeker/lib/alert-areas";
import {
  APPSEC_DOWNLOAD_KIND,
  APPSEC_FINDING_PARAM,
  APPSEC_FINDING_SORT,
  APPSEC_FINDING_SORT_LABEL,
  APPSEC_FIRST_SEEN_DAYS,
  APPSEC_FIX_FILTER,
  APPSEC_PRIORITIES,
  APPSEC_SEVERITIES,
  APPSEC_STATES,
  appSecCategoryLabel,
  appSecDownloadHref,
  type AppSecFindingFilters,
  appSecFindingHref,
  appSecFindingLocation,
  appSecFindingsHref,
  appSecFindingsQuery,
  appSecFixSummary,
  appSecPriorityLabel,
  appSecSeverityLabel,
  appSecStateLabel,
  type AppSecWorkspace,
  attributesOf,
  dueLabel,
  formatAppSecDate,
  hasLegacyAppSecParams,
  isAppSecFiltered,
  optionsInScope,
  parseAppSecFindingFilters,
  selectedIds,
} from "@/cloudsneeker/lib/appsec";
import {
  TRIAGE_STATUS_FILTERS,
  triageStatusLabel,
} from "@/cloudsneeker/lib/finding-triage";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { loadAllTargets } from "@/cloudsneeker/lib/trivy-targets-data";
import { TABLE_FRAME_CLASS } from "@/cloudsneeker/lib/ui-classes";
import {
  APPSEC_CATEGORY,
  type AppSecFindingAttributes,
  type AppSecFindingsSummary,
  type AppSecResource,
} from "@/cloudsneeker/types/appsec";
import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";
import { TRIVY_MODE } from "@/cloudsneeker/types/trivy";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { cn } from "@/lib/utils";
import type { SearchParamsProps } from "@/types";

import {
  AppSecPriorityBadge,
  AppSecSeverityBadge,
  AppSecStateBadge,
  LoadError,
  ROW_LINK_CLASS,
  TABLE_CLASS,
  TD_CLASS,
  TD_PRIMARY_CLASS,
  TH_CLASS,
} from "./appsec-ui";
import { pagesOf } from "./area-triage-view";
import { EmptyState } from "./empty-state";
import { FindingTriageStatusBadge } from "./finding-triage-status-badge";
import { PageHeader } from "./page-header";
import { PageNav } from "./page-nav";
import { SortSelect } from "./standard/sort-select";
import { StandardFilters } from "./standard/standard-filters";
import type { StandardFilter } from "./standard/standard-filters.utils";
import { StandardTableCard } from "./standard/standard-table-card";
import { StatTile } from "./stat-tile";

interface AppSecFindingsWorkspaceProps {
  workspace: AppSecWorkspace;
  searchParams: SearchParamsProps;
}

/** One finding workspace: figures, filters and the paginated findings table. */
export const AppSecFindingsWorkspace = ({
  workspace,
  searchParams,
}: AppSecFindingsWorkspaceProps) => {
  const filters = parseAppSecFindingFilters(searchParams);
  if (hasLegacyAppSecParams(searchParams)) {
    redirect(appSecFindingsHref(workspace.segment, filters));
  }
  const exportQuery = appSecFindingsQuery(workspace.category, filters, {
    paginate: false,
  });
  return (
    <ContentLayout title={workspace.title} icon={<ShieldAlert />}>
      <PageHeader
        description={workspace.description}
        actions={
          <>
            <Button asChild size="sm" variant="outline">
              <a
                href={appSecDownloadHref(
                  APPSEC_DOWNLOAD_KIND.FINDINGS,
                  "csv",
                  exportQuery,
                )}
              >
                <Download aria-hidden="true" />
                CSV
              </a>
            </Button>
            <Button asChild size="sm" variant="outline">
              <a
                href={appSecDownloadHref(
                  APPSEC_DOWNLOAD_KIND.FINDINGS,
                  "json",
                  exportQuery,
                )}
              >
                <Download aria-hidden="true" />
                JSON
              </a>
            </Button>
            <Button asChild size="sm" variant="outline">
              <Link href={newAlertHref(FINDING_AREA.APPLICATION_SECURITY)}>
                Create alert
              </Link>
            </Button>
          </>
        }
      />
      <Suspense
        key={JSON.stringify(filters)}
        fallback={<Skeleton className="h-96 w-full rounded-xl" />}
      >
        <SSRWorkspace workspace={workspace} filters={filters} />
      </Suspense>
    </ContentLayout>
  );
};

const SummaryTiles = ({
  workspace,
  summary,
}: {
  workspace: AppSecWorkspace;
  summary: AppSecFindingsSummary;
}) => {
  const href = (filters: Partial<AppSecFindingFilters>) =>
    appSecFindingsHref(workspace.segment, filters);
  const severity = summary.by_severity;
  const isVulnerabilities =
    workspace.category === APPSEC_CATEGORY.VULNERABILITY;
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
      <StatTile
        label="Active"
        value={summary.active}
        hint="New, open and reopened"
        href={href({})}
      />
      <StatTile
        label="Critical"
        value={severity.critical ?? 0}
        tone="critical"
        href={href({ severities: ["critical"] })}
      />
      <StatTile
        label="High"
        value={severity.high ?? 0}
        tone="high"
        href={href({ severities: ["high"] })}
      />
      <StatTile
        label="Urgent priority"
        value={summary.by_priority.urgent ?? 0}
        tone="danger"
        hint="Calculated, not scanner severity"
        href={href({ priorities: ["urgent"] })}
      />
      <StatTile
        label="Past deadline"
        value={summary.overdue}
        tone="warning"
        href={href({ overdue: true })}
      />
      <StatTile
        label="Fixed"
        value={summary.by_state.fixed ?? 0}
        tone="success"
        hint={`${summary.suppressed} suppressed`}
        href={href({ states: ["fixed"] })}
      />
      {isVulnerabilities ? (
        <>
          <StatTile
            label="Instances"
            value={summary.vulnerabilities.instances}
            hint="Vulnerability, package and location"
          />
          <StatTile
            label="Unique advisories"
            value={summary.vulnerabilities.unique_ids}
          />
          <StatTile
            label="Affected packages"
            value={summary.vulnerabilities.affected_packages}
          />
          <StatTile
            label="Fix available"
            value={summary.vulnerabilities.fixable}
            tone="success"
            href={href({ fix: APPSEC_FIX_FILTER.AVAILABLE })}
          />
          <StatTile
            label="No fix yet"
            value={summary.vulnerabilities.unfixed}
            href={href({ fix: APPSEC_FIX_FILTER.NONE })}
          />
        </>
      ) : null}
    </div>
  );
};

interface FilterChoice {
  value: string;
  label: string;
}

/** The workspace's filter bar (Cloud Security Findings controls). */
export const buildAppSecFilters = ({
  workspace,
  applications,
  targets,
  targetTypes = Object.values(TRIVY_MODE),
}: {
  workspace: AppSecWorkspace;
  applications: FilterChoice[];
  targets: FilterChoice[];
  /** Asset types to offer; every type when not given. */
  targetTypes?: readonly string[];
}): StandardFilter[] => {
  const param = APPSEC_FINDING_PARAM;
  const filters: StandardFilter[] = [
    {
      key: param.SEVERITY,
      label: "Severities",
      options: APPSEC_SEVERITIES.map((severity) => ({
        value: severity,
        label: appSecSeverityLabel(severity),
      })),
    },
    {
      key: param.PRIORITY,
      label: "Priorities",
      options: APPSEC_PRIORITIES.map((priority) => ({
        value: priority,
        label: appSecPriorityLabel(priority),
      })),
    },
    {
      key: param.STATE,
      label: "States (active)",
      options: APPSEC_STATES.map((state) => ({
        value: state,
        label: appSecStateLabel(state),
      })),
    },
    {
      key: param.TRIAGE,
      label: "Triage Statuses",
      options: TRIAGE_STATUS_FILTERS.map((status) => ({
        value: status,
        label: triageStatusLabel(status),
      })),
    },
  ];
  if (applications.length > 0) {
    filters.push({
      key: param.APPLICATION,
      label: "Applications",
      wide: true,
      options: applications,
    });
  }
  if (targets.length > 0) {
    filters.push({
      key: param.TARGET,
      label: "Targets",
      wide: true,
      options: targets,
    });
  }
  if (targetTypes.length > 0) {
    filters.push({
      key: param.ASSET_TYPE,
      label: "Asset Types",
      options: targetTypes.map((mode) => ({
        value: mode,
        label: labelForTrivyMode(mode),
      })),
    });
  }
  filters.push({
    key: param.FIRST_SEEN,
    label: "Time (first seen)",
    single: true,
    options: APPSEC_FIRST_SEEN_DAYS.map((days) => ({
      value: String(days),
      label: days === 1 ? "Last 24 hours" : `Last ${days} days`,
    })),
  });
  if (workspace.category === APPSEC_CATEGORY.VULNERABILITY) {
    filters.push({
      key: param.FIX,
      label: "Fix States",
      single: true,
      options: [
        { value: "true", label: "Fix available" },
        { value: "false", label: "No fix yet" },
      ],
    });
  }
  filters.push(
    {
      key: param.OVERDUE,
      label: "Deadlines",
      single: true,
      options: [{ value: "true", label: "Past deadline" }],
    },
    {
      key: param.SUPPRESSED,
      label: "Findings (suppressed hidden)",
      single: true,
      options: [{ value: "true", label: "Suppressed only" }],
    },
  );
  return filters;
};

/** Rule and package scopes come from links (components, finding detail);
 * they show as removable notes above the table. */
const ScopeNotes = ({
  workspace,
  filters,
}: {
  workspace: AppSecWorkspace;
  filters: AppSecFindingFilters;
}) => {
  const scopes = [
    filters.rule
      ? {
          label: `Rule: ${filters.rule}`,
          href: appSecFindingsHref(workspace.segment, {
            ...filters,
            rule: null,
            page: 1,
          }),
        }
      : null,
    filters.pkg
      ? {
          label: `Package: ${filters.pkg}`,
          href: appSecFindingsHref(workspace.segment, {
            ...filters,
            pkg: null,
            page: 1,
          }),
        }
      : null,
  ].filter((scope) => scope !== null);
  if (scopes.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs">
      <span className="text-text-neutral-secondary">Scoped to</span>
      {scopes.map((scope) => (
        <Link
          key={scope.label}
          href={scope.href}
          className="border-border-neutral-secondary text-text-neutral-primary hover:bg-bg-neutral-tertiary inline-flex items-center gap-1 rounded-full border px-2.5 py-1"
          aria-label={`Remove ${scope.label}`}
        >
          {scope.label}
          <X className="size-3" aria-hidden="true" />
        </Link>
      ))}
    </div>
  );
};

const FindingsTable = ({
  workspace,
  findings,
}: {
  workspace: AppSecWorkspace;
  findings: AppSecResource<AppSecFindingAttributes>[];
}) => (
  <div className={TABLE_FRAME_CLASS}>
    <table className={TABLE_CLASS}>
      <thead>
        <tr>
          <th scope="col" className={TH_CLASS}>
            Priority
          </th>
          <th scope="col" className={TH_CLASS}>
            Severity
          </th>
          <th scope="col" className={TH_CLASS}>
            Finding
          </th>
          <th scope="col" className={TH_CLASS}>
            Where
          </th>
          <th scope="col" className={TH_CLASS}>
            Asset
          </th>
          <th scope="col" className={TH_CLASS}>
            State
          </th>
          <th scope="col" className={TH_CLASS}>
            Triage
          </th>
          <th scope="col" className={TH_CLASS}>
            Deadline
          </th>
        </tr>
      </thead>
      <tbody>
        {findings.map(({ id, attributes }) => {
          const fix = appSecFixSummary(attributes);
          return (
            <tr key={id}>
              <td className={TD_CLASS}>
                <AppSecPriorityBadge
                  priority={attributes.priority}
                  score={attributes.priority_score}
                />
              </td>
              <td className={TD_CLASS}>
                <AppSecSeverityBadge severity={attributes.severity} />
              </td>
              <td className={cn(TD_PRIMARY_CLASS, "max-w-md")}>
                <Link href={appSecFindingHref(id)} className={ROW_LINK_CLASS}>
                  {attributes.rule_id || attributes.title}
                </Link>
                <p className="text-text-neutral-secondary line-clamp-2 text-xs">
                  {workspace.category === null
                    ? `${appSecCategoryLabel(attributes.category)} · `
                    : ""}
                  {attributes.title}
                </p>
              </td>
              <td className={cn(TD_CLASS, "max-w-xs")}>
                <span className="text-text-neutral-primary break-all">
                  {appSecFindingLocation(attributes)}
                </span>
                {fix ? (
                  <p className="text-text-neutral-tertiary text-xs">{fix}</p>
                ) : null}
              </td>
              <td className={cn(TD_CLASS, "max-w-48")}>
                <span className="text-text-neutral-primary block truncate">
                  {attributes.application_name ?? attributes.target_name}
                </span>
                <span className="text-text-neutral-tertiary block truncate text-xs">
                  {attributes.application_name
                    ? `${attributes.target_name} · `
                    : ""}
                  {labelForTrivyMode(attributes.target_type)}
                </span>
              </td>
              <td className={TD_CLASS}>
                <AppSecStateBadge state={attributes.state} />
                <p className="text-text-neutral-tertiary mt-1 text-xs whitespace-nowrap">
                  Since{" "}
                  {formatAppSecDate(attributes.first_seen_at).slice(0, 10)}
                </p>
              </td>
              <td className={TD_CLASS}>
                <FindingTriageStatusBadge status={attributes.triage_status} />
              </td>
              <td className={cn(TD_CLASS, "text-xs whitespace-nowrap")}>
                {attributes.state === "fixed"
                  ? `Fixed ${formatAppSecDate(attributes.fixed_at).slice(0, 10)}`
                  : dueLabel(attributes.due_at)}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  </div>
);

const SSRWorkspace = async ({
  workspace,
  filters,
}: {
  workspace: AppSecWorkspace;
  filters: AppSecFindingFilters;
}) => {
  // The tiles describe the scope (application, target, rule), not the chips.
  const scope = {
    ...parseAppSecFindingFilters({}),
    target: filters.target,
    application: filters.application,
    rule: filters.rule,
    pkg: filters.pkg,
  };
  const [response, summaryResponse, applicationsResponse, loadedTargets] =
    await Promise.all([
      listAppSecFindings(appSecFindingsQuery(workspace.category, filters)),
      getAppSecFindingsSummary(
        appSecFindingsQuery(workspace.category, scope, { paginate: false }),
      ),
      listAppSecApplications({ "page[size]": "100", sort: "name" }),
      loadAllTargets({}, "name"),
    ]);
  const applicationOptions: FilterChoice[] = isListResponse(
    applicationsResponse,
  )
    ? responseList<AppSecResource<{ name?: string }>>(applicationsResponse).map(
        (item) => ({ value: item.id, label: item.attributes.name || item.id }),
      )
    : [];
  const targetOptions: FilterChoice[] = (loadedTargets?.targets ?? []).map(
    (target) => ({
      value: target.id,
      label: target.attributes.name || target.id,
    }),
  );
  // Offer only values with findings in this workspace: an asset type, target
  // or application without any would always combine to an empty list.
  const facets = attributesOf<AppSecFindingsSummary>(summaryResponse)?.facets;
  const scopedApplications = optionsInScope(
    applicationOptions,
    facets?.applications,
    selectedIds(filters.application),
  );
  const scopedTargets = optionsInScope(
    targetOptions,
    facets?.targets,
    selectedIds(filters.target),
  );
  const scopedTargetTypes = optionsInScope(
    Object.values(TRIVY_MODE).map((value) => ({ value })),
    facets?.target_types,
    filters.assetTypes,
  ).map((option) => option.value);
  const reloadHref = appSecFindingsHref(workspace.segment, filters);
  if (!isListResponse(response)) {
    return (
      <LoadError title="Findings" what="Findings" reloadHref={reloadHref} />
    );
  }
  const findings =
    responseList<AppSecResource<AppSecFindingAttributes>>(response);
  const total = responseCount(response) ?? findings.length;
  const summary = attributesOf<AppSecFindingsSummary>(summaryResponse);
  const filtered = isAppSecFiltered(filters);
  const sortOptions = Object.values(APPSEC_FINDING_SORT).map((sort) => ({
    value: sort,
    label: APPSEC_FINDING_SORT_LABEL[sort],
  }));

  return (
    <div className="flex flex-col gap-6">
      {summary ? (
        <SummaryTiles workspace={workspace} summary={summary} />
      ) : null}
      <StandardFilters
        testIdPrefix={`appsec-${workspace.segment || "findings"}`}
        filters={buildAppSecFilters({
          workspace,
          applications: scopedApplications,
          targets: scopedTargets,
          targetTypes: scopedTargetTypes,
        })}
      />
      <ScopeNotes workspace={workspace} filters={filters} />
      <StandardTableCard
        searchPlaceholder="Search rule, package, file or title (press Enter)"
        total={total}
        toolbarRight={
          <SortSelect
            value={filters.sort}
            defaultValue={APPSEC_FINDING_SORT.PRIORITY}
            options={sortOptions}
          />
        }
        footer={
          <PageNav
            page={filters.page}
            pages={pagesOf(response)}
            count={total}
            noun="findings"
            pageSize={filters.pageSize}
            hrefFor={(page) =>
              appSecFindingsHref(workspace.segment, { ...filters, page })
            }
          />
        }
      >
        {findings.length === 0 ? (
          <EmptyState
            title={filtered ? "No findings match" : "No findings"}
            description={
              filtered
                ? "Clear a filter to see more findings."
                : workspace.empty
            }
            action={
              filtered ? (
                <Button asChild size="sm" variant="outline">
                  <Link href={appSecFindingsHref(workspace.segment)}>
                    Clear filters
                  </Link>
                </Button>
              ) : undefined
            }
          />
        ) : (
          <FindingsTable workspace={workspace} findings={findings} />
        )}
      </StandardTableCard>
    </div>
  );
};
