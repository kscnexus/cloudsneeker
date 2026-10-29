// Interactive report body shared by the in-app page (/reports/<runId>) and
// the public share page (/shared-reports/<token>). Renders the JSON payload
// from `ReportData.to_dict()`; holds no state itself so it renders on the
// server, with chart and paging islands on the client.

import type { ReactNode } from "react";

import { reportTitle } from "@/cloudsneeker/lib/report-catalog";
import {
  formatCell,
  formatKpi,
  formatReportDate,
  formatReportDay,
  frameworkLabel,
  humanizeKey,
  severityChartData,
  severityLabel,
  sourceColumns,
  sourceRowLabel,
} from "@/cloudsneeker/lib/report-view";
import type { ReportPayload } from "@/cloudsneeker/types/reports";
import { HorizontalBarChart, LineChart } from "@/components/graphs";

import { ReportDetailTable } from "./report-detail-table";
import { ReportScoreRing } from "./report-score-ring";
import { ReportSeverityBadge } from "./report-severity-badge";

interface ReportViewProps {
  report: ReportPayload;
  /** Controls shown in the header (downloads, share, print). */
  actions?: ReactNode;
  /** Product wordmark row for the public page. */
  brandHeader?: ReactNode;
}

const TREND_LINES = [
  { dataKey: "fail", label: "Open issues", color: "var(--bg-fail-primary)" },
  {
    dataKey: "critical",
    label: "Critical",
    color: "var(--color-bg-data-critical)",
  },
  { dataKey: "high", label: "High", color: "var(--color-bg-data-high)" },
  { dataKey: "pass", label: "Passed", color: "var(--bg-pass-primary)" },
];

const Section = ({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: ReactNode;
}) => (
  <section className="border-border-neutral-secondary bg-bg-neutral-secondary flex flex-col gap-4 rounded-xl border p-5 break-inside-avoid-page print:border-0 print:p-0">
    <div className="flex flex-col gap-1">
      <h2 className="text-text-neutral-primary text-lg font-semibold">
        {title}
      </h2>
      {description ? (
        <p className="text-text-neutral-secondary text-sm">{description}</p>
      ) : null}
    </div>
    {children}
  </section>
);

const filterSummary = (report: ReportPayload): string[] => {
  const { filters } = report;
  const parts: string[] = [];
  const providers = filters.provider_ids?.length ?? 0;
  parts.push(providers === 0 ? "All sources" : `${providers} source(s)`);
  if (filters.date_from || filters.date_to) {
    parts.push(
      `${formatReportDay(filters.date_from) || "Start"} – ${formatReportDay(filters.date_to) || "today"}`,
    );
  }
  if (filters.severity_floor) {
    parts.push(`${severityLabel(filters.severity_floor)} and above`);
  }
  if (filters.compliance_id) {
    parts.push(frameworkLabel(filters.compliance_id));
  }
  return parts;
};

export const ReportView = ({ report, actions, brandHeader }: ReportViewProps) => {
  const kpis = Object.entries(report.kpis ?? {});
  const severityData = severityChartData(report.severity_totals ?? {});
  const hasSeverity = severityData.some((item) => item.value > 0);
  const trend = report.trend ?? [];
  const risks = report.top_risks ?? [];
  const sources = report.sources ?? [];
  const sourceKeys = sourceColumns(sources);
  const compliance = report.compliance ?? [];
  const actionsList = report.remediation ?? [];
  const tables = report.tables ?? [];
  const status = report.status_totals;

  return (
    <article
      className="flex flex-col gap-6 print:gap-4"
      data-report-view=""
      data-report-type={report.report_type}
    >
      {brandHeader}

      <header className="border-border-neutral-secondary bg-bg-neutral-secondary flex flex-col gap-6 rounded-xl border p-6 md:flex-row md:items-center print:border-0 print:p-0">
        <ReportScoreRing score={report.score} grade={report.grade} />
        <div className="flex min-w-0 flex-1 flex-col gap-2">
          <p className="text-text-neutral-tertiary text-xs font-semibold tracking-wider uppercase">
            {reportTitle(report.report_type, report.title)}
          </p>
          <h1 className="text-text-neutral-primary text-2xl font-bold">
            {report.title}
          </h1>
          {report.headline ? (
            <p className="text-text-neutral-secondary text-base">
              {report.headline}
            </p>
          ) : null}
          <p className="text-text-neutral-tertiary text-xs">
            Generated {formatReportDate(report.generated_at)} ·{" "}
            {filterSummary(report).join(" · ")}
          </p>
        </div>
        {actions ? (
          <div className="flex flex-wrap gap-2 print:hidden">{actions}</div>
        ) : null}
      </header>

      {report.empty_state ? (
        <Section title="Nothing to report yet">
          <p className="text-text-neutral-secondary text-sm">
            {report.empty_state}
          </p>
        </Section>
      ) : null}

      {kpis.length > 0 ? (
        <ul
          aria-label="Key figures"
          className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-4"
        >
          {kpis.map(([key, value]) => (
            <li
              key={key}
              className="border-border-neutral-secondary bg-bg-neutral-secondary flex flex-col gap-1 rounded-xl border p-4 break-inside-avoid"
            >
              <span className="text-text-neutral-secondary text-xs">
                {humanizeKey(key)}
              </span>
              <span className="text-text-neutral-primary text-2xl font-semibold">
                {formatKpi(key, value)}
              </span>
            </li>
          ))}
        </ul>
      ) : null}

      {!report.empty_state ? (
        <div className="grid gap-6 lg:grid-cols-2">
          <Section
            title="Open issues by severity"
            description={
              status
                ? `${formatCell(status.fail)} failing · ${formatCell(status.pass)} passing · ${formatCell(status.muted)} muted`
                : undefined
            }
          >
            {hasSeverity ? (
              <HorizontalBarChart data={severityData} />
            ) : (
              <p className="text-text-neutral-secondary text-sm">
                No open issues in scope.
              </p>
            )}
          </Section>

          <Section title="Trend" description="Open issues across recent scans.">
            {trend.length > 1 ? (
              <LineChart
                data={trend.map((point) => ({ ...point }))}
                lines={TREND_LINES}
                height={280}
              />
            ) : (
              <p className="text-text-neutral-secondary text-sm">
                A trend appears after two or more scans.
              </p>
            )}
          </Section>
        </div>
      ) : null}

      {risks.length > 0 ? (
        <Section
          title="Top risks"
          description="Ranked by severity and how many resources each affects."
        >
          <ol className="flex flex-col gap-3">
            {risks.map((risk, index) => (
              <li
                key={`${risk.check_id}-${index}`}
                className="border-border-neutral-secondary flex flex-col gap-2 rounded-lg border p-4 break-inside-avoid"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-text-neutral-tertiary text-xs font-semibold">
                    #{index + 1}
                  </span>
                  <ReportSeverityBadge severity={risk.severity} />
                  <span className="text-text-neutral-primary font-medium">
                    {risk.title || risk.check_id}
                  </span>
                  <span className="text-text-neutral-tertiary ml-auto text-xs">
                    {formatCell(risk.resources ?? 0)} resource(s) ·{" "}
                    {formatCell(risk.findings ?? 0)} finding(s)
                  </span>
                </div>
                {risk.impact ? (
                  <p className="text-text-neutral-secondary text-sm">
                    <span className="text-text-neutral-primary font-medium">
                      Business impact:{" "}
                    </span>
                    {risk.impact}
                  </p>
                ) : null}
                {risk.remediation ? (
                  <p className="text-text-neutral-secondary text-sm">
                    <span className="text-text-neutral-primary font-medium">
                      Recommended fix:{" "}
                    </span>
                    {risk.remediation}
                  </p>
                ) : null}
              </li>
            ))}
          </ol>
        </Section>
      ) : null}

      {sources.length > 0 ? (
        <Section title="Breakdown by source">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-border-neutral-secondary border-b">
                  <th scope="col" className="text-text-neutral-secondary px-3 py-2 text-xs font-semibold">
                    Source
                  </th>
                  {sourceKeys.map((key) => (
                    <th
                      key={key}
                      scope="col"
                      className="text-text-neutral-secondary px-3 py-2 text-right text-xs font-semibold whitespace-nowrap"
                    >
                      {humanizeKey(key)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-border-neutral-secondary divide-y">
                {sources.map((row, index) => (
                  <tr key={`source-${index}`}>
                    <td className="text-text-neutral-primary px-3 py-2 font-medium">
                      {sourceRowLabel(row)}
                    </td>
                    {sourceKeys.map((key) => (
                      <td
                        key={key}
                        className="text-text-neutral-primary px-3 py-2 text-right tabular-nums"
                      >
                        {formatCell(row[key])}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      ) : null}

      {compliance.length > 0 ? (
        <Section
          title="Compliance posture"
          description="Share of requirements passing per framework."
        >
          <ul className="flex flex-col gap-3">
            {compliance.map((item) => {
              const pct = item.pass_pct ?? 0;
              return (
                <li key={item.compliance_id} className="flex flex-col gap-1 break-inside-avoid">
                  <div className="flex items-center justify-between gap-2 text-sm">
                    <span className="text-text-neutral-primary font-medium">
                      {frameworkLabel(item.compliance_id)}
                    </span>
                    <span className="text-text-neutral-secondary tabular-nums">
                      {item.pass_pct === null ? "—" : `${Math.round(pct)}%`} ·{" "}
                      {item.passed}/{item.total} passed
                    </span>
                  </div>
                  <div
                    className="bg-bg-neutral-tertiary h-2 w-full overflow-hidden rounded-full"
                    role="progressbar"
                    aria-label={`${frameworkLabel(item.compliance_id)} pass rate`}
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={Math.round(pct)}
                  >
                    <div
                      className="bg-bg-pass-primary h-full rounded-full"
                      style={{ width: `${Math.max(0, Math.min(100, pct))}%` }}
                    />
                  </div>
                </li>
              );
            })}
          </ul>
        </Section>
      ) : null}

      {actionsList.length > 0 ? (
        <Section title="Next actions" description="What to do first.">
          <ol className="flex flex-col gap-2">
            {actionsList.map((item) => (
              <li
                key={`action-${item.priority}`}
                className="flex gap-3 text-sm break-inside-avoid"
              >
                <span className="bg-button-primary flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-bold text-black">
                  {item.priority}
                </span>
                <div className="flex flex-col gap-0.5">
                  <span className="text-text-neutral-primary">
                    {item.action || item.title}
                  </span>
                  {item.why || (item.title && item.action) ? (
                    <span className="text-text-neutral-tertiary text-xs">
                      {item.why ?? item.title}
                      {item.severity ? ` · ${severityLabel(item.severity)}` : ""}
                      {item.resources ? ` · ${item.resources} resource(s)` : ""}
                    </span>
                  ) : null}
                </div>
              </li>
            ))}
          </ol>
        </Section>
      ) : null}

      {tables.map((table) => (
        <ReportDetailTable key={table.key} table={table} />
      ))}
    </article>
  );
};
