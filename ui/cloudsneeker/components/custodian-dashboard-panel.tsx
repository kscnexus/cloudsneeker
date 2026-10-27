import Link from "next/link";

import type { CustodianDashboardMetrics } from "@/cloudsneeker/lib/custodian-dashboard";
import { Badge } from "@/components/shadcn/badge/badge";
import { Card, CardContent } from "@/components/shadcn/card/card";
import {
  Section,
  SectionContent,
  SectionDescription,
  SectionHeader,
  SectionTitle,
} from "@/components/shadcn/section/section";

interface CustodianDashboardPanelProps {
  metrics: CustodianDashboardMetrics;
}

const MetricCard = ({
  label,
  value,
  hint,
}: {
  label: string;
  value: number | string;
  hint?: string;
}) => (
  <Card variant="base" padding="none" className="shadow-sm">
    <CardContent className="flex flex-col gap-1 p-4">
      <span className="text-text-neutral-secondary text-xs font-medium uppercase tracking-wide">
        {label}
      </span>
      <span className="text-text-neutral-primary text-2xl font-semibold">
        {value}
      </span>
      {hint ? (
        <span className="text-text-neutral-tertiary text-xs">{hint}</span>
      ) : null}
    </CardContent>
  </Card>
);

export const CustodianDashboardPanel = ({
  metrics,
}: CustodianDashboardPanelProps) => {
  return (
    <div className="flex flex-col gap-6">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard
          label="Policies"
          value={metrics.policyCount}
          hint={`${metrics.scheduledPolicyCount} scheduled`}
        />
        <MetricCard
          label="Dry-runs"
          value={metrics.runCount}
          hint={`${metrics.activeRunCount} in progress`}
        />
        <MetricCard
          label="Completed"
          value={metrics.completedRunCount}
          hint={`${metrics.failedRunCount} failed`}
        />
        <MetricCard
          label="Resources matched"
          value={metrics.resourcesMatched}
          hint="Across completed dry-runs"
        />
      </div>

      {metrics.findingSuggestions.length > 0 ? (
        <Section>
          <SectionHeader>
            <SectionTitle>Suggested from Findings</SectionTitle>
            <SectionDescription>
              Failed Findings checks that map to Custodian dry-run starters.
            </SectionDescription>
          </SectionHeader>
          <SectionContent>
            <ul className="divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-xl border">
              {metrics.findingSuggestions.map((item) => (
                <li
                  key={`${item.checkId}-${item.templateId}`}
                  className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
                >
                  <div className="flex min-w-0 flex-col gap-0.5">
                    <span className="text-text-neutral-primary text-sm font-medium">
                      {item.templateName}
                    </span>
                    <span className="text-text-neutral-secondary text-xs">
                      {item.checkId} · {item.providerType}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Link
                      href={item.findingsHref}
                      className="text-text-neutral-secondary text-xs hover:underline"
                    >
                      View findings
                    </Link>
                    <Link
                      href={item.newPolicyHref}
                      className="text-text-neutral-primary text-xs font-medium hover:underline"
                    >
                      Create Custodian dry-run
                    </Link>
                  </div>
                </li>
              ))}
            </ul>
          </SectionContent>
        </Section>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-2">
        <Section>
          <SectionHeader>
            <SectionTitle>Recent dry-runs</SectionTitle>
            <SectionDescription>
              Latest Custodian dry-run activity across all policies.
            </SectionDescription>
          </SectionHeader>
          <SectionContent>
            {metrics.recentRuns.length === 0 ? (
              <p className="text-text-neutral-secondary text-sm">
                No dry-runs yet. Create a policy and run a dry-run to populate
                the dashboard.
              </p>
            ) : (
              <ul className="divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-xl border">
                {metrics.recentRuns.map((row) => (
                  <li key={row.runId} className="flex flex-col gap-1 px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link
                        href={`/custodian/${row.policyId}/runs/${row.runId}`}
                        className="text-text-neutral-primary text-sm font-medium hover:underline"
                      >
                        {row.policyName}
                      </Link>
                      <Badge variant="tag" className="capitalize">
                        {row.status}
                      </Badge>
                      <span className="text-text-neutral-secondary text-xs capitalize">
                        {row.trigger}
                      </span>
                    </div>
                    <div className="text-text-neutral-secondary flex flex-wrap gap-3 text-xs">
                      <Link
                        href={`/custodian/${row.policyId}/runs/${row.runId}`}
                        className="hover:underline"
                      >
                        Resources:{" "}
                        {row.resourcesMatched === null
                          ? "—"
                          : row.resourcesMatched}
                      </Link>
                      {row.insertedAt ? (
                        <span>
                          {new Date(row.insertedAt).toLocaleString()}
                        </span>
                      ) : null}
                    </div>
                    {row.error ? (
                      <p className="text-text-error text-xs">{row.error}</p>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </SectionContent>
        </Section>

        <Section>
          <SectionHeader>
            <SectionTitle>Top policies by resources</SectionTitle>
            <SectionDescription>
              Policies whose completed dry-runs matched the most resources.
            </SectionDescription>
          </SectionHeader>
          <SectionContent>
            {metrics.topPolicies.length === 0 ? (
              <p className="text-text-neutral-secondary text-sm">
                Run a completed dry-run to see policy rankings.
              </p>
            ) : (
              <ul className="divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-xl border">
                {metrics.topPolicies.map((row) => (
                  <li
                    key={row.policyId}
                    className="flex items-center justify-between gap-3 px-4 py-3"
                  >
                    <div className="flex min-w-0 flex-col gap-0.5">
                      <Link
                        href={`/custodian/${row.policyId}`}
                        className="text-text-neutral-primary truncate text-sm font-medium hover:underline"
                      >
                        {row.policyName}
                      </Link>
                      <span className="text-text-neutral-secondary text-xs">
                        {row.providerLabel} · {row.runCount} runs
                      </span>
                    </div>
                    <span className="text-text-neutral-primary text-sm font-semibold">
                      {row.resourcesMatched}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </SectionContent>
        </Section>
      </div>

      <Section>
        <SectionHeader>
          <SectionTitle>Resource-match trends</SectionTitle>
          <SectionDescription>
            Completed dry-runs with new / gone deltas versus the prior run.
          </SectionDescription>
        </SectionHeader>
        <SectionContent>
          {metrics.resourceTrends.length === 0 ? (
            <p className="text-text-neutral-secondary text-sm">
              Trends appear after completed dry-runs report matched resources.
            </p>
          ) : (
            <ul className="divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-xl border">
              {metrics.resourceTrends.map((row) => (
                <li
                  key={row.runId}
                  className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
                >
                  <div className="flex min-w-0 flex-col gap-0.5">
                    <Link
                      href={`/custodian/${row.policyId}/runs/${row.runId}`}
                      className="text-text-neutral-primary truncate text-sm font-medium hover:underline"
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
        </SectionContent>
      </Section>
    </div>
  );
};
