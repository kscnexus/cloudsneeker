// Pure helpers for the Overview risk view. The executive report already
// scores every product area (cloud, application security, compliance and
// governance); the Overview reads its latest completed run.

import { BRAND } from "@/cloudsneeker/brand";
import { openFindingsHref } from "@/cloudsneeker/lib/findings-links";
import { appSecurityHref, governanceHref, reportsHref } from "@/cloudsneeker/routes";
import {
  REPORT_RUN_STATUS,
  REPORT_SEVERITY_ORDER,
  type ReportCellValue,
  type ReportPayload,
  type ReportRisk,
  type ReportRunResource,
  type ReportSeverity,
  type ReportSourceRow,
} from "@/cloudsneeker/types/reports";

export const RISK_DOMAIN = {
  CLOUD: "cloud",
  APPLICATION: "application",
  COMPLIANCE: "compliance",
  GOVERNANCE: "governance",
} as const;

export type RiskDomain = (typeof RISK_DOMAIN)[keyof typeof RISK_DOMAIN];

/** Display order of the area tiles. */
export const RISK_DOMAIN_ORDER = [
  RISK_DOMAIN.CLOUD,
  RISK_DOMAIN.APPLICATION,
  RISK_DOMAIN.COMPLIANCE,
  RISK_DOMAIN.GOVERNANCE,
] as const;

export const RISK_DOMAIN_LABEL: Record<RiskDomain, string> = {
  cloud: "Cloud posture",
  application: BRAND.appSecurityName,
  compliance: "Compliance",
  governance: BRAND.governanceName,
};

export const RISK_DOMAIN_HREF: Record<RiskDomain, string> = {
  cloud: openFindingsHref(),
  application: appSecurityHref(),
  compliance: "/compliance",
  governance: governanceHref(),
};

export const TOP_RISK_LIMIT = 5;
export const TREND_POINT_LIMIT = 12;

export interface RiskDomainSummary {
  domain: RiskDomain;
  label: string;
  score: number | null;
  grade: string;
  openIssues: number;
  critical: number;
  high: number;
  coverage: string;
  href: string;
  hasData: boolean;
}

export interface RiskSeverityTotal {
  severity: ReportSeverity;
  count: number;
  href: string;
}

export interface RiskTopItem {
  checkId: string;
  title: string;
  severity: string;
  findings: number | null;
  resources: number | null;
  service: string;
  href: string;
}

export interface RiskTrendBar {
  date: string;
  fail: number;
  critical: number;
  /** Bar height relative to the busiest point, 0-100. */
  heightPct: number;
  /** Share of the bar that is critical, 0-100. */
  criticalPct: number;
}

export interface RiskOverviewModel {
  runId: string;
  reportHref: string;
  generatedAt: string;
  headline: string;
  score: number | null;
  grade: string;
  openIssues: number;
  sourcesInScope: number | null;
  severityTotals: RiskSeverityTotal[];
  domains: RiskDomainSummary[];
  topRisks: RiskTopItem[];
  trend: RiskTrendBar[];
  /** Open issues now minus the first trend point; `null` without a trend. */
  trendDelta: number | null;
  isEmpty: boolean;
}

const toNumber = (value: unknown): number | null => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
};

const toText = (value: ReportCellValue | undefined): string =>
  typeof value === "string" ? value : value == null ? "" : String(value);

const isRiskDomain = (value: unknown): value is RiskDomain =>
  typeof value === "string" &&
  (RISK_DOMAIN_ORDER as readonly string[]).includes(value);

/** Newest completed executive run, or `null`. `runs` are newest first. */
export const latestCompletedRun = (
  runs: ReportRunResource[],
): ReportRunResource | null =>
  runs.find((run) => run.attributes.status === REPORT_RUN_STATUS.COMPLETED) ??
  null;

/** A newer executive run is still being prepared. */
export const hasNewerActiveRun = (
  runs: ReportRunResource[],
  latest: ReportRunResource | null,
): boolean => {
  for (const run of runs) {
    if (latest && run.id === latest.id) return false;
    if (
      run.attributes.status === REPORT_RUN_STATUS.PENDING ||
      run.attributes.status === REPORT_RUN_STATUS.RUNNING
    ) {
      return true;
    }
  }
  return false;
};

/** Report payload of a `/report-runs/<id>/data` response, if present. */
export const reportPayloadFrom = (response: unknown): ReportPayload | null => {
  if (!response || typeof response !== "object") return null;
  const data = (response as { data?: unknown }).data;
  if (!data || typeof data !== "object" || Array.isArray(data)) return null;
  const attributes = (data as { attributes?: unknown }).attributes;
  if (!attributes || typeof attributes !== "object") return null;
  return attributes as ReportPayload;
};

export const buildDomainSummaries = (
  sources: ReportSourceRow[] | undefined,
): RiskDomainSummary[] => {
  const rows = new Map<RiskDomain, ReportSourceRow>();
  for (const row of sources ?? []) {
    const domain = row.domain;
    if (isRiskDomain(domain)) rows.set(domain, row);
  }
  return RISK_DOMAIN_ORDER.map((domain) => {
    const row = rows.get(domain);
    const score = toNumber(row?.score);
    return {
      domain,
      label: RISK_DOMAIN_LABEL[domain],
      score,
      grade: score === null ? "—" : toText(row?.grade) || "—",
      openIssues: toNumber(row?.open_issues) ?? 0,
      critical: toNumber(row?.critical) ?? 0,
      high: toNumber(row?.high) ?? 0,
      coverage: toText(row?.coverage),
      href: RISK_DOMAIN_HREF[domain],
      hasData: score !== null,
    };
  });
};

export const buildSeverityTotals = (
  totals: Partial<Record<ReportSeverity, number>> | undefined,
): RiskSeverityTotal[] =>
  REPORT_SEVERITY_ORDER.map((severity) => ({
    severity,
    count: toNumber(totals?.[severity]) ?? 0,
    href: openFindingsHref({ "filter[severity__in]": severity }),
  }));

export const buildTopRisks = (
  risks: ReportRisk[] | undefined,
  limit = TOP_RISK_LIMIT,
): RiskTopItem[] =>
  (risks ?? []).slice(0, limit).map((risk) => ({
    checkId: risk.check_id,
    title: risk.title || risk.check_id,
    severity: risk.severity,
    findings: toNumber(risk.findings),
    resources: toNumber(risk.resources),
    service: typeof risk.service === "string" ? risk.service : "",
    href: openFindingsHref({ "filter[check_id__in]": risk.check_id }),
  }));

export const buildTrendBars = (
  trend: ReportPayload["trend"] | undefined,
  limit = TREND_POINT_LIMIT,
): RiskTrendBar[] => {
  const points = (trend ?? []).slice(-limit);
  const peak = Math.max(0, ...points.map((point) => toNumber(point.fail) ?? 0));
  return points.map((point) => {
    const fail = toNumber(point.fail) ?? 0;
    const critical = Math.min(fail, toNumber(point.critical) ?? 0);
    return {
      date: point.date,
      fail,
      critical,
      heightPct: peak > 0 ? Math.max(4, Math.round((fail / peak) * 100)) : 4,
      criticalPct: fail > 0 ? Math.round((critical / fail) * 100) : 0,
    };
  });
};

export const buildRiskOverview = (
  report: ReportPayload,
  runId: string,
): RiskOverviewModel => {
  const trend = buildTrendBars(report.trend);
  const openIssues =
    toNumber(report.kpis?.open_issues) ?? toNumber(report.status_totals?.fail) ?? 0;
  const firstTrend = trend[0];
  const lastTrend = trend[trend.length - 1];
  return {
    runId,
    reportHref: reportsHref(runId),
    generatedAt: report.generated_at,
    headline: report.headline,
    score: toNumber(report.score),
    grade: report.grade || "—",
    openIssues,
    sourcesInScope: toNumber(report.kpis?.sources_in_scope),
    severityTotals: buildSeverityTotals(report.severity_totals),
    domains: buildDomainSummaries(report.sources),
    topRisks: buildTopRisks(report.top_risks),
    trend,
    trendDelta:
      firstTrend && lastTrend && trend.length > 1
        ? lastTrend.fail - firstTrend.fail
        : null,
    isEmpty: Boolean(report.empty_state),
  };
};
