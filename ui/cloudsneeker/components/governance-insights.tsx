import { ClipboardCheck, FileBarChart, ShieldCheck } from "lucide-react";
import Link from "next/link";

import {
  BAR_TONE,
  BarList,
  type BarListItem,
} from "@/cloudsneeker/components/dashboard/bar-list";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { STAT_TILE_TONE, StatTile } from "@/cloudsneeker/components/stat-tile";
import { areaTriagePageHref } from "@/cloudsneeker/lib/area-findings";
import type { ProviderFindingRow } from "@/cloudsneeker/lib/dashboard-data";
import {
  type ComplianceFrameworkRow,
  type ComplianceSummary,
  percentOf,
  rankFrameworksByGap,
  REMEDIATION_STATUS_LABEL,
  type RemediationProgress,
} from "@/cloudsneeker/lib/dashboards";
import { openFindingsHref } from "@/cloudsneeker/lib/findings-links";
import {
  TABLE_BODY_CLASS,
  TABLE_CLASS,
  TABLE_FRAME_CLASS,
  TABLE_HEAD_CLASS,
  TABLE_HEADER_CELL_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import { reportsHref } from "@/cloudsneeker/routes";
import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";
import { Button } from "@/components/shadcn";
import { cn } from "@/lib/utils";
import { FINDING_TRIAGE_STATUS } from "@/types/findings-triage";
import { getProviderDisplayName } from "@/types/providers";

const COMPLIANCE_PATH = "/compliance";
const MUTELIST_PATH = "/mutelist";
const FRAMEWORK_TABLE_LIMIT = 12;

const formatCount = (value: number | null | undefined): string =>
  value === null || value === undefined ? "—" : value.toLocaleString("en-US");

const scoreTone = (score: number | null) =>
  score === null
    ? STAT_TILE_TONE.NEUTRAL
    : score >= 80
      ? STAT_TILE_TONE.SUCCESS
      : score >= 50
        ? STAT_TILE_TONE.WARNING
        : STAT_TILE_TONE.DANGER;

const scoreFill = (score: number): string =>
  score >= 80 ? "bg-bg-pass" : score >= 50 ? "bg-bg-warning" : "bg-bg-fail";

/** Triage states that record a decision rather than a fix. */
const RISK_DECISION_STATUSES = [
  FINDING_TRIAGE_STATUS.UNDER_REVIEW,
  FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
  FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
  FINDING_TRIAGE_STATUS.REMEDIATING,
  FINDING_TRIAGE_STATUS.RESOLVED,
] as const;

export interface GovernanceInsightsProps {
  frameworks: ComplianceFrameworkRow[] | null;
  compliance: ComplianceSummary | null;
  providerFindings: ProviderFindingRow[] | null;
  /** Connected cloud accounts and sources, or null. */
  accountCount: number | null;
  /** Cloud findings by triage state (risk decisions), or null. */
  riskDecisions: RemediationProgress | null;
}

const FrameworkTable = ({ rows }: { rows: ComplianceFrameworkRow[] }) => (
  <div className={TABLE_FRAME_CLASS}>
    <table className={TABLE_CLASS}>
      <caption className="sr-only">
        Compliance by framework, most failed requirements first
      </caption>
      <thead className={TABLE_HEAD_CLASS}>
        <tr>
          <th scope="col" className={TABLE_HEADER_CELL_CLASS}>
            Framework
          </th>
          <th scope="col" className={cn(TABLE_HEADER_CELL_CLASS, "w-40")}>
            Score
          </th>
          <th scope="col" className={cn(TABLE_HEADER_CELL_CLASS, "text-right")}>
            Requirements
          </th>
          <th scope="col" className={cn(TABLE_HEADER_CELL_CLASS, "text-right")}>
            Passed
          </th>
          <th scope="col" className={cn(TABLE_HEADER_CELL_CLASS, "text-right")}>
            Failed
          </th>
          <th scope="col" className={cn(TABLE_HEADER_CELL_CLASS, "text-right")}>
            Manual
          </th>
        </tr>
      </thead>
      <tbody className={TABLE_BODY_CLASS}>
        {rows.map((row) => (
          <tr key={row.id}>
            <th scope="row" className="px-3 py-2 text-left font-medium">
              <Link
                href={COMPLIANCE_PATH}
                className="hover:text-text-lighthouse underline-offset-4 hover:underline"
              >
                {row.label}
              </Link>
            </th>
            <td className="px-3 py-2">
              <span className="flex items-center gap-2">
                <span
                  aria-hidden="true"
                  className="bg-bg-neutral-tertiary block h-1.5 w-20 overflow-hidden rounded-full"
                >
                  <span
                    className={cn("block h-full", scoreFill(row.score))}
                    style={{ width: `${row.score}%` }}
                  />
                </span>
                <span className="tabular-nums">{row.score}%</span>
              </span>
            </td>
            <td className="px-3 py-2 text-right tabular-nums">
              {formatCount(row.total)}
            </td>
            <td className="text-text-success-primary px-3 py-2 text-right tabular-nums">
              {formatCount(row.passed)}
            </td>
            <td className="text-text-error-primary px-3 py-2 text-right tabular-nums">
              {formatCount(row.failed)}
            </td>
            <td className="text-text-neutral-secondary px-3 py-2 text-right tabular-nums">
              {formatCount(row.manual)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

/**
 * Governance dashboard sections above the policy dashboard: overview,
 * compliance frameworks, controls, findings by provider, and risk decisions.
 * Compliance numbers come from the compliance watchlist API, the same source
 * as the Compliance page cards.
 */
export const GovernanceInsights = ({
  frameworks,
  compliance,
  providerFindings,
  accountCount,
  riskDecisions,
}: GovernanceInsightsProps) => {
  const ranked = frameworks ? rankFrameworksByGap(frameworks) : [];
  const providerMax = Math.max(
    1,
    ...(providerFindings ?? []).map((row) => row.pass + row.fail),
  );

  const controlBars: BarListItem[] = compliance
    ? [
        {
          id: "passed",
          label: "Passed",
          value: formatCount(compliance.passed),
          percent: percentOf(compliance.passed, compliance.total) ?? 0,
          tone: BAR_TONE.PASS,
        },
        {
          id: "failed",
          label: "Failed",
          value: formatCount(compliance.failed),
          percent: percentOf(compliance.failed, compliance.total) ?? 0,
          tone: BAR_TONE.FAIL,
        },
        {
          id: "manual",
          label: "Manual review",
          value: formatCount(compliance.manual),
          percent: percentOf(compliance.manual, compliance.total) ?? 0,
          tone: BAR_TONE.WARNING,
          hint: "No automated check; confirm these with evidence.",
        },
      ]
    : [];

  const decisionBars: BarListItem[] = riskDecisions
    ? RISK_DECISION_STATUSES.map((status) => {
        const count =
          riskDecisions.counts.find((row) => row.status === status)?.count ?? 0;
        return {
          id: status,
          label: REMEDIATION_STATUS_LABEL[status],
          value: formatCount(count),
          percent: percentOf(count, riskDecisions.total) ?? 0,
          tone:
            status === FINDING_TRIAGE_STATUS.RESOLVED
              ? BAR_TONE.PASS
              : status === FINDING_TRIAGE_STATUS.RISK_ACCEPTED
                ? BAR_TONE.WARNING
                : BAR_TONE.NEUTRAL,
          href: areaTriagePageHref(FINDING_AREA.CLOUD, status),
        };
      })
    : [];

  return (
    <div className="flex flex-col gap-6">
      <ul
        aria-label="Governance figures"
        className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4"
      >
        <li className="min-w-0">
          <StatTile
            label="Compliance score"
            icon={<ShieldCheck />}
            tone={scoreTone(compliance?.percent ?? null)}
            value={
              compliance?.percent === null || compliance?.percent === undefined
                ? "—"
                : `${compliance.percent}%`
            }
            hint={
              compliance
                ? `${compliance.frameworkCount} framework${compliance.frameworkCount === 1 ? "" : "s"}, latest scans`
                : "Could not be loaded"
            }
            href={COMPLIANCE_PATH}
          />
        </li>
        <li className="min-w-0">
          <StatTile
            label="Controls passed"
            tone={STAT_TILE_TONE.SUCCESS}
            value={formatCount(compliance?.passed)}
            hint={
              compliance
                ? `of ${formatCount(compliance.total)} requirements`
                : undefined
            }
          />
        </li>
        <li className="min-w-0">
          <StatTile
            label="Controls failed"
            tone={STAT_TILE_TONE.DANGER}
            value={formatCount(compliance?.failed)}
            hint={
              compliance
                ? `${formatCount(compliance.manual)} need manual review`
                : undefined
            }
          />
        </li>
        <li className="min-w-0">
          <StatTile
            label="Cloud accounts"
            value={formatCount(accountCount)}
            hint="Connected sources in scope"
            href="/providers"
          />
        </li>
      </ul>

      <SectionCard
        title="Compliance frameworks"
        description="Frameworks evaluated in the latest scan of each account, most failed requirements first."
        actions={
          <Button asChild variant="ghost" size="sm">
            <Link href={COMPLIANCE_PATH}>Open Compliance</Link>
          </Button>
        }
      >
        {frameworks === null ? (
          <EmptyState
            title="Compliance could not be loaded"
            description="The service did not answer. Reload the page in a moment."
          />
        ) : ranked.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck />}
            title="No compliance results yet"
            description="Frameworks appear here after the first completed cloud scan."
            action={
              <Button asChild size="sm">
                <Link href="/scans">Launch a scan</Link>
              </Button>
            }
          />
        ) : (
          <FrameworkTable rows={ranked.slice(0, FRAMEWORK_TABLE_LIMIT)} />
        )}
        {ranked.length > FRAMEWORK_TABLE_LIMIT ? (
          <p className="text-text-neutral-tertiary text-xs">
            Showing {FRAMEWORK_TABLE_LIMIT} of {ranked.length} frameworks.
            Compliance lists every framework with its requirements.
          </p>
        ) : null}
      </SectionCard>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard
          title="Security controls"
          description="Requirement results across every framework above."
        >
          <BarList
            label="Requirements by result"
            items={controlBars}
            emptyMessage="No requirement results yet."
          />
        </SectionCard>
        <SectionCard
          title="Findings by cloud provider"
          description="Passed and failed checks in the latest scan of each provider."
        >
          {providerFindings === null ? (
            <p className="text-text-neutral-tertiary text-sm">
              Provider results could not be loaded.
            </p>
          ) : (
            <BarList
              label="Failed checks by provider"
              items={providerFindings.map((row) => ({
                id: row.type,
                label: getProviderDisplayName(row.type),
                value: `${formatCount(row.fail)} failed`,
                percent: ((row.pass + row.fail) / providerMax) * 100,
                tone:
                  row.fail === 0
                    ? BAR_TONE.PASS
                    : (percentOf(row.fail, row.pass + row.fail) ?? 0) > 25
                      ? BAR_TONE.FAIL
                      : BAR_TONE.WARNING,
                hint: `${formatCount(row.pass)} passed · ${formatCount(row.resources)} resources`,
                href: openFindingsHref({
                  "filter[provider_type__in]": row.type,
                }),
              }))}
              emptyMessage="No cloud scan results yet."
            />
          )}
        </SectionCard>
      </div>

      <SectionCard
        title="Audit and risk"
        description="Decisions recorded on open cloud findings, exceptions and evidence for auditors."
      >
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[2fr_1fr]">
          {riskDecisions ? (
            <BarList
              label="Cloud findings by triage decision"
              items={decisionBars}
              emptyMessage="No triage decisions yet."
              className="sm:grid sm:grid-cols-2 sm:gap-x-6"
            />
          ) : (
            <p className="text-text-neutral-tertiary text-sm">
              Triage decisions could not be loaded.
            </p>
          )}
          <div className="flex flex-col gap-2">
            <Button
              asChild
              variant="outline"
              size="sm"
              className="justify-start"
            >
              <Link
                href={areaTriagePageHref(
                  FINDING_AREA.CLOUD,
                  FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
                )}
              >
                <ClipboardCheck aria-hidden="true" />
                Accepted risks
              </Link>
            </Button>
            <Button
              asChild
              variant="outline"
              size="sm"
              className="justify-start"
            >
              <Link href={MUTELIST_PATH}>
                <ShieldCheck aria-hidden="true" />
                Exceptions (mutelist)
              </Link>
            </Button>
            <Button
              asChild
              variant="outline"
              size="sm"
              className="justify-start"
            >
              <Link href={reportsHref()}>
                <FileBarChart aria-hidden="true" />
                Compliance evidence reports
              </Link>
            </Button>
          </div>
        </div>
      </SectionCard>
    </div>
  );
};
