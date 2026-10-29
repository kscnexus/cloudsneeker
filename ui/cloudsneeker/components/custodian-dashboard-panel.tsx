import Link from "next/link";

import type { CustodianDashboardMetrics } from "@/cloudsneeker/lib/custodian-dashboard";
import { CARD_LIST_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { governanceHref } from "@/cloudsneeker/routes";
import { cn } from "@/lib/utils";

import { RunStatusBadge } from "./run-status-badge";
import { SectionCard } from "./section-card";
import { STAT_TILE_TONE, StatTile } from "./stat-tile";

interface CustodianDashboardPanelProps {
  metrics: CustodianDashboardMetrics;
}

const LINK_CLASS = "rounded-sm underline-offset-2 hover:underline";

export const CustodianDashboardPanel = ({
  metrics,
}: CustodianDashboardPanelProps) => {
  return (
    <div className="flex flex-col gap-6">
      <ul
        aria-label="Key figures"
        className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4"
      >
        <li className="min-w-0">
          <StatTile
            label="Policies"
            value={metrics.policyCount}
            hint={`${metrics.scheduledPolicyCount} scheduled`}
            tone={STAT_TILE_TONE.ACCENT}
          />
        </li>
        <li className="min-w-0">
          <StatTile
            label="Dry-runs"
            value={metrics.runCount}
            hint={`${metrics.activeRunCount} in progress`}
          />
        </li>
        <li className="min-w-0">
          <StatTile
            label="Completed"
            value={metrics.completedRunCount}
            hint={`${metrics.failedRunCount} failed`}
            tone={
              metrics.failedRunCount > 0
                ? STAT_TILE_TONE.WARNING
                : STAT_TILE_TONE.SUCCESS
            }
          />
        </li>
        <li className="min-w-0">
          <StatTile
            label="Resources matched"
            value={metrics.resourcesMatched}
            hint="Across completed dry-runs"
            tone={
              metrics.resourcesMatched > 0
                ? STAT_TILE_TONE.HIGH
                : STAT_TILE_TONE.NEUTRAL
            }
          />
        </li>
      </ul>

      {metrics.findingSuggestions.length > 0 ? (
        <SectionCard
          title="Suggested from Findings"
          description="Failed Findings checks that map to governance dry-run starters."
        >
          <ul className={CARD_LIST_CLASS}>
            {metrics.findingSuggestions.map((item) => (
              <li
                key={`${item.checkId}-${item.templateId}`}
                className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
              >
                <div className="flex min-w-0 flex-col gap-0.5">
                  <span className="text-text-neutral-primary text-sm font-medium">
                    {item.templateName}
                  </span>
                  <span className="text-text-neutral-secondary text-xs break-all">
                    {item.checkId} · {item.providerType}
                  </span>
                </div>
                <div className="flex flex-wrap gap-3">
                  <Link
                    href={item.findingsHref}
                    className={cn("text-text-neutral-secondary text-xs", LINK_CLASS)}
                  >
                    View findings
                  </Link>
                  <Link
                    href={item.newPolicyHref}
                    className={cn("text-button-tertiary text-xs font-medium", LINK_CLASS)}
                  >
                    Create governance dry-run
                  </Link>
                </div>
              </li>
            ))}
          </ul>
        </SectionCard>
      ) : null}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <SectionCard
          title="Recent dry-runs"
          description="Latest governance dry-run activity across all policies."
        >
          {metrics.recentRuns.length === 0 ? (
            <p className="text-text-neutral-secondary text-sm">
              No dry-runs yet. Create a policy and run a dry-run to populate
              the dashboard.
            </p>
          ) : (
            <ul className={CARD_LIST_CLASS}>
              {metrics.recentRuns.map((row) => (
                <li key={row.runId} className="flex flex-col gap-1 px-4 py-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <Link
                      href={governanceHref(row.policyId, "runs", row.runId)}
                      className={cn("text-text-neutral-primary min-w-0 text-sm font-medium break-words", LINK_CLASS)}
                    >
                      {row.policyName}
                    </Link>
                    <RunStatusBadge status={row.status} />
                  </div>
                  <div className="text-text-neutral-secondary flex flex-wrap gap-3 text-xs">
                    <span className="capitalize">{row.trigger}</span>
                    <Link
                      href={governanceHref(row.policyId, "runs", row.runId)}
                      className={LINK_CLASS}
                    >
                      Resources:{" "}
                      {row.resourcesMatched === null
                        ? "—"
                        : row.resourcesMatched}
                    </Link>
                    {row.insertedAt ? (
                      <span>{new Date(row.insertedAt).toLocaleString()}</span>
                    ) : null}
                  </div>
                  {row.error ? (
                    <p
                      className="text-text-error-primary line-clamp-2 text-xs break-all"
                      title={row.error}
                    >
                      {row.error}
                    </p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </SectionCard>

        <SectionCard
          title="Top policies by resources"
          description="Policies whose completed dry-runs matched the most resources."
        >
          {metrics.topPolicies.length === 0 ? (
            <p className="text-text-neutral-secondary text-sm">
              Run a completed dry-run to see policy rankings.
            </p>
          ) : (
            <ul className={CARD_LIST_CLASS}>
              {metrics.topPolicies.map((row) => (
                <li
                  key={row.policyId}
                  className="flex items-center justify-between gap-3 px-4 py-3"
                >
                  <div className="flex min-w-0 flex-col gap-0.5">
                    <Link
                      href={governanceHref(row.policyId)}
                      className={cn("text-text-neutral-primary truncate text-sm font-medium", LINK_CLASS)}
                    >
                      {row.policyName}
                    </Link>
                    <span className="text-text-neutral-secondary text-xs">
                      {row.providerLabel} · {row.runCount} runs
                    </span>
                  </div>
                  <span className="text-text-neutral-primary text-sm font-semibold tabular-nums">
                    {row.resourcesMatched}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </SectionCard>
      </div>

      <SectionCard
        title="Resource-match trends"
        description="Completed dry-runs with new / gone deltas versus the prior run."
      >
        {metrics.resourceTrends.length === 0 ? (
          <p className="text-text-neutral-secondary text-sm">
            Trends appear after completed dry-runs report matched resources.
          </p>
        ) : (
          <ul className={CARD_LIST_CLASS}>
            {metrics.resourceTrends.map((row) => (
              <li
                key={row.runId}
                className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
              >
                <div className="flex min-w-0 flex-col gap-0.5">
                  <Link
                    href={governanceHref(row.policyId, "runs", row.runId)}
                    className={cn("text-text-neutral-primary truncate text-sm font-medium", LINK_CLASS)}
                  >
                    {row.policyName}
                  </Link>
                  <span className="text-text-neutral-secondary text-xs">
                    {new Date(row.insertedAt).toLocaleString()}
                  </span>
                </div>
                <div className="text-text-neutral-secondary flex flex-wrap gap-3 text-xs">
                  <span className="text-text-neutral-primary font-semibold">
                    {row.resourcesMatched} matched
                  </span>
                  <span>+{row.deltaNew} new</span>
                  <span>-{row.deltaGone} gone</span>
                </div>
              </li>
            ))}
          </ul>
        )}
      </SectionCard>
    </div>
  );
};
