import { Gauge } from "lucide-react";
import Link from "next/link";

import { formatReportDate, formatReportDay } from "@/cloudsneeker/lib/report-view";
import type {
  RiskOverviewModel,
  RiskTopItem,
  RiskTrendBar,
} from "@/cloudsneeker/lib/risk-overview";
import { CARD_LIST_CLASS, FOCUS_RING_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { reportsHref } from "@/cloudsneeker/routes";
import { Button } from "@/components/shadcn";
import { cn } from "@/lib/utils";

import { EmptyState } from "./empty-state";
import { ReportScoreRing } from "./report-score-ring";
import { ReportSeverityBadge } from "./report-severity-badge";
import { RiskOverviewRefreshButton } from "./risk-overview-refresh-button";
import { SectionCard } from "./section-card";
import { SeverityBreakdown } from "./severity-breakdown";
import { STAT_TILE_TONE, StatTile, type StatTileTone } from "./stat-tile";

export const RISK_OVERVIEW_TITLE = "Risk overview";

const RISK_OVERVIEW_DESCRIPTION =
  "One score across cloud posture, application security, compliance and governance.";

interface RiskOverviewPanelProps {
  /** `null` when no executive report has completed yet. */
  model: RiskOverviewModel | null;
  /** A newer report is being prepared. */
  refreshing?: boolean;
}

const gradeTone = (score: number | null): StatTileTone => {
  if (score === null) return STAT_TILE_TONE.NEUTRAL;
  if (score >= 80) return STAT_TILE_TONE.SUCCESS;
  if (score >= 60) return STAT_TILE_TONE.WARNING;
  return STAT_TILE_TONE.DANGER;
};

const RefreshingNote = () => (
  <p className="text-text-neutral-tertiary text-xs" role="status">
    Updating — reload the page in a minute to see the new score.
  </p>
);

const TopRiskList = ({ risks }: { risks: RiskTopItem[] }) => {
  if (risks.length === 0) {
    return (
      <p className="text-text-neutral-secondary text-sm">
        No open risks in the latest results.
      </p>
    );
  }
  return (
    <ol className={CARD_LIST_CLASS}>
      {risks.map((risk) => (
        <li key={risk.checkId}>
          <Link
            href={risk.href}
            className={cn(
              "hover:bg-bg-neutral-tertiary flex flex-col gap-1 px-3 py-2.5 transition-colors sm:flex-row sm:items-center sm:justify-between sm:gap-3",
              FOCUS_RING_CLASS,
            )}
          >
            <span className="text-text-neutral-primary min-w-0 text-sm font-medium break-words">
              {risk.title}
            </span>
            <span className="flex shrink-0 items-center gap-2">
              <ReportSeverityBadge severity={risk.severity} />
              {risk.resources !== null ? (
                <span className="text-text-neutral-secondary text-xs tabular-nums">
                  {risk.resources} resource{risk.resources === 1 ? "" : "s"}
                </span>
              ) : null}
            </span>
          </Link>
        </li>
      ))}
    </ol>
  );
};

const TrendBars = ({
  bars,
  delta,
}: {
  bars: RiskTrendBar[];
  delta: number | null;
}) => {
  if (bars.length < 2) {
    return (
      <p className="text-text-neutral-secondary text-sm">
        The trend appears after more than one day of results.
      </p>
    );
  }
  const first = bars[0];
  const last = bars[bars.length - 1];
  return (
    <div className="flex flex-col gap-2">
      <div
        role="img"
        aria-label={`Open issues went from ${first.fail} on ${formatReportDay(first.date)} to ${last.fail} on ${formatReportDay(last.date)}`}
        className="flex h-28 items-end gap-1"
      >
        {bars.map((bar) => (
          <span
            key={bar.date}
            title={`${formatReportDay(bar.date)}: ${bar.fail} open, ${bar.critical} critical`}
            className="bg-button-tertiary/40 relative flex flex-1 flex-col justify-end overflow-hidden rounded-t-sm"
            style={{ height: `${bar.heightPct}%` }}
          >
            <span
              className="bg-bg-data-critical w-full"
              style={{ height: `${bar.criticalPct}%` }}
            />
          </span>
        ))}
      </div>
      <div className="text-text-neutral-tertiary flex justify-between text-xs">
        <span>{formatReportDay(first.date)}</span>
        <span>{formatReportDay(last.date)}</span>
      </div>
      {delta !== null ? (
        <p className="text-text-neutral-secondary text-sm">
          {delta === 0
            ? "No change in open issues over this period."
            : delta < 0
              ? `${Math.abs(delta)} fewer open issues over this period.`
              : `${delta} more open issues over this period.`}
        </p>
      ) : null}
    </div>
  );
};

export const RiskOverviewPanel = ({
  model,
  refreshing = false,
}: RiskOverviewPanelProps) => {
  if (!model) {
    return (
      <SectionCard
        title={RISK_OVERVIEW_TITLE}
        description={RISK_OVERVIEW_DESCRIPTION}
      >
        <EmptyState
          icon={<Gauge />}
          title="No risk score yet"
          description="Build the risk view to score cloud posture, application security, compliance and governance in one place. It refreshes every time an executive report runs."
          action={
            refreshing ? (
              <RefreshingNote />
            ) : (
              <>
                <RiskOverviewRefreshButton label="Build risk view" />
                <Button asChild variant="ghost" size="sm">
                  <Link href={reportsHref()}>Open reports</Link>
                </Button>
              </>
            )
          }
        />
      </SectionCard>
    );
  }

  return (
    <SectionCard
      title={RISK_OVERVIEW_TITLE}
      description={`${RISK_OVERVIEW_DESCRIPTION} As of ${formatReportDate(model.generatedAt)}.`}
      actions={
        <>
          {refreshing ? null : <RiskOverviewRefreshButton label="Refresh" />}
          <Button asChild variant="ghost" size="sm">
            <Link href={model.reportHref}>Full report</Link>
          </Button>
        </>
      }
    >
      {refreshing ? <RefreshingNote /> : null}

      <div className="flex flex-col gap-6 lg:flex-row lg:items-center">
        <div className="flex items-center gap-4">
          <ReportScoreRing score={model.score} grade={model.grade} size={128} />
          <div className="flex max-w-xs flex-col gap-1">
            <span className="text-text-neutral-primary text-3xl font-semibold tabular-nums">
              {model.openIssues.toLocaleString("en-US")}
            </span>
            <span className="text-text-neutral-secondary text-sm">
              open issues
              {model.sourcesInScope !== null
                ? ` across ${model.sourcesInScope} source${model.sourcesInScope === 1 ? "" : "s"}`
                : ""}
            </span>
            {model.headline ? (
              <p className="text-text-neutral-tertiary text-xs">
                {model.headline}
              </p>
            ) : null}
          </div>
        </div>
        <SeverityBreakdown
          className="min-w-0 flex-1"
          items={model.severityTotals}
        />
      </div>

      <ul
        aria-label="Score by area"
        className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4"
      >
        {model.domains.map((domain) => (
          <li key={domain.domain} className="min-w-0">
            <StatTile
              label={domain.label}
              href={domain.href}
              tone={gradeTone(domain.score)}
              value={
                domain.hasData ? (
                  <>
                    {domain.grade}
                    <span className="text-text-neutral-tertiary ml-2 text-sm font-normal">
                      {Math.round(domain.score ?? 0)} / 100
                    </span>
                  </>
                ) : (
                  "—"
                )
              }
              hint={
                domain.hasData
                  ? [
                      `${domain.openIssues} open`,
                      domain.critical > 0 ? `${domain.critical} critical` : "",
                      domain.coverage,
                    ]
                      .filter(Boolean)
                      .join(" · ")
                  : "Not connected yet"
              }
            />
          </li>
        ))}
      </ul>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="flex min-w-0 flex-col gap-2">
          <h3 className="text-text-neutral-primary text-sm font-semibold">
            Top risks
          </h3>
          <TopRiskList risks={model.topRisks} />
        </div>
        <div className="flex min-w-0 flex-col gap-2">
          <h3 className="text-text-neutral-primary text-sm font-semibold">
            Open issues over time
          </h3>
          <TrendBars bars={model.trend} delta={model.trendDelta} />
        </div>
      </div>
    </SectionCard>
  );
};
