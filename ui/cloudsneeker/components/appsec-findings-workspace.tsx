import { Download, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import {
  getAppSecFindingsSummary,
  listAppSecFindings,
} from "@/cloudsneeker/actions/appsec";
import {
  APPSEC_DOWNLOAD_KIND,
  APPSEC_FINDING_PARAM,
  APPSEC_FINDING_SORT,
  APPSEC_FINDING_SORT_LABEL,
  APPSEC_FIX_FILTER,
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
  appSecSeverityLabel,
  appSecStateLabel,
  type AppSecWorkspace,
  attributesOf,
  dueLabel,
  formatAppSecDate,
  isAppSecFiltered,
  parseAppSecFindingFilters,
  toggleItem,
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
import { FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import {
  APPSEC_CATEGORY,
  type AppSecFindingAttributes,
  type AppSecFindingsSummary,
  type AppSecResource,
} from "@/cloudsneeker/types/appsec";
import { Button, Input, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { cn } from "@/lib/utils";
import type { SearchParamsProps } from "@/types";

import {
  AppSecPriorityBadge,
  AppSecSeverityBadge,
  AppSecStateBadge,
  ChipLink,
  LoadError,
  Pager,
  ROW_LINK_CLASS,
  TABLE_CLASS,
  TABLE_WRAPPER_CLASS,
  TD_CLASS,
  TD_PRIMARY_CLASS,
  TH_CLASS,
} from "./appsec-ui";
import { pagesOf } from "./area-triage-view";
import { EmptyState } from "./empty-state";
import { FindingTriageStatusBadge } from "./finding-triage-status-badge";
import { PageHeader } from "./page-header";
import { SectionCard } from "./section-card";
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

const Filters = ({
  workspace,
  filters,
}: {
  workspace: AppSecWorkspace;
  filters: AppSecFindingFilters;
}) => {
  const reset = { ...filters, page: 1 };
  const href = (next: Partial<AppSecFindingFilters>) =>
    appSecFindingsHref(workspace.segment, { ...reset, ...next });
  const param = APPSEC_FINDING_PARAM;
  const hidden: [string, string][] = [
    [param.SEVERITY, filters.severities.join(",")],
    [param.STATE, filters.states.join(",")],
    [param.PRIORITY, filters.priorities.join(",")],
    [param.TRIAGE, filters.triage ?? ""],
    [param.FIX, filters.fix ?? ""],
    [param.OVERDUE, filters.overdue ? "1" : ""],
    [param.SUPPRESSED, filters.suppressed ? "1" : ""],
    [param.TARGET, filters.target ?? ""],
    [param.APPLICATION, filters.application ?? ""],
    [param.RULE, filters.rule ?? ""],
    [param.PACKAGE, filters.pkg ?? ""],
  ];
  return (
    <div className="flex flex-col gap-3">
      <nav aria-label="Severity" className="flex flex-wrap gap-2">
        {APPSEC_SEVERITIES.map((severity) => (
          <ChipLink
            key={severity}
            href={href({
              severities: toggleItem(filters.severities, severity),
            })}
            active={filters.severities.includes(severity)}
          >
            {appSecSeverityLabel(severity)}
          </ChipLink>
        ))}
      </nav>
      <nav aria-label="Detection state" className="flex flex-wrap gap-2">
        {APPSEC_STATES.map((state) => (
          <ChipLink
            key={state}
            href={href({ states: toggleItem(filters.states, state) })}
            active={filters.states.includes(state)}
          >
            {appSecStateLabel(state)}
          </ChipLink>
        ))}
        <ChipLink
          href={href({ suppressed: !filters.suppressed })}
          active={filters.suppressed}
        >
          Suppressed
        </ChipLink>
        {workspace.category === APPSEC_CATEGORY.VULNERABILITY ||
        workspace.category === null ? (
          <>
            <ChipLink
              href={href({
                fix:
                  filters.fix === APPSEC_FIX_FILTER.AVAILABLE
                    ? null
                    : APPSEC_FIX_FILTER.AVAILABLE,
              })}
              active={filters.fix === APPSEC_FIX_FILTER.AVAILABLE}
            >
              Fix available
            </ChipLink>
            <ChipLink
              href={href({
                fix:
                  filters.fix === APPSEC_FIX_FILTER.NONE
                    ? null
                    : APPSEC_FIX_FILTER.NONE,
              })}
              active={filters.fix === APPSEC_FIX_FILTER.NONE}
            >
              No fix yet
            </ChipLink>
          </>
        ) : null}
      </nav>
      <nav aria-label="Triage status" className="flex flex-wrap gap-2">
        {[null, ...TRIAGE_STATUS_FILTERS].map((status) => (
          <ChipLink
            key={status ?? "any"}
            href={href({ triage: status })}
            active={status === filters.triage}
          >
            {status ? triageStatusLabel(status) : "Any triage status"}
          </ChipLink>
        ))}
      </nav>
      <form method="get" className="flex flex-wrap items-end gap-2">
        {hidden.map(([name, value]) =>
          value ? (
            <input key={name} type="hidden" name={name} value={value} />
          ) : null,
        )}
        <label className="flex min-w-48 flex-1 flex-col gap-1 text-xs">
          <span className="text-text-neutral-secondary font-semibold">
            Search
          </span>
          <Input
            name={param.SEARCH}
            defaultValue={filters.search}
            placeholder={`${workspace.ruleLabel}, title, package, file or resource`}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="text-text-neutral-secondary font-semibold">
            Sort by
          </span>
          <select
            name={param.SORT}
            defaultValue={filters.sort}
            className={cn(FORM_SELECT_CLASS, "w-40")}
          >
            {Object.values(APPSEC_FINDING_SORT).map((sort) => (
              <option key={sort} value={sort}>
                {APPSEC_FINDING_SORT_LABEL[sort]}
              </option>
            ))}
          </select>
        </label>
        <Button type="submit" size="sm">
          Apply
        </Button>
        <Button asChild size="sm" variant="ghost">
          <Link href={appSecFindingsHref(workspace.segment)}>Reset</Link>
        </Button>
      </form>
      {filters.target || filters.application || filters.rule || filters.pkg ? (
        <p className="text-text-neutral-tertiary text-xs">
          Scoped to{" "}
          {[
            filters.application ? "one application" : null,
            filters.target ? "one target" : null,
            filters.rule
              ? `${workspace.ruleLabel.toLowerCase()} ${filters.rule}`
              : null,
            filters.pkg ? `package ${filters.pkg}` : null,
          ]
            .filter(Boolean)
            .join(", ")}
          .{" "}
          <Link
            className="underline"
            href={href({
              target: null,
              application: null,
              rule: null,
              pkg: null,
            })}
          >
            Remove scope
          </Link>
        </p>
      ) : null}
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
  <div className={TABLE_WRAPPER_CLASS}>
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
  const [response, summaryResponse] = await Promise.all([
    listAppSecFindings(appSecFindingsQuery(workspace.category, filters)),
    getAppSecFindingsSummary(
      appSecFindingsQuery(workspace.category, scope, { paginate: false }),
    ),
  ]);
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

  return (
    <div className="flex flex-col gap-6">
      {summary ? (
        <SummaryTiles workspace={workspace} summary={summary} />
      ) : null}
      <SectionCard
        title="Findings"
        description={`${total} finding(s) match. A finding keeps one row across scans; triage follows it.`}
      >
        <Filters workspace={workspace} filters={filters} />
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
        <Pager
          page={filters.page}
          pages={pagesOf(response)}
          hrefFor={(page) =>
            appSecFindingsHref(workspace.segment, { ...filters, page })
          }
        />
      </SectionCard>
    </div>
  );
};
