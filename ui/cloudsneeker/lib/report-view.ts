// Pure helpers for the report pages (in-app, public share, and run list).

import {
  REPORT_RUN_STATUS,
  REPORT_SEVERITY_ORDER,
  type ReportCellValue,
  type ReportRunStatus,
  type ReportSeverity,
  type ReportSourceRow,
} from "@/cloudsneeker/types/reports";

export const REPORT_DETAIL_PAGE_SIZE = 25;

export const isReportRunActive = (status: string): boolean =>
  status === REPORT_RUN_STATUS.PENDING || status === REPORT_RUN_STATUS.RUNNING;

export const REPORT_STATUS_LABEL: Record<ReportRunStatus, string> = {
  [REPORT_RUN_STATUS.PENDING]: "Queued",
  [REPORT_RUN_STATUS.RUNNING]: "Generating",
  [REPORT_RUN_STATUS.COMPLETED]: "Ready",
  [REPORT_RUN_STATUS.FAILED]: "Failed",
};

export const reportStatusLabel = (status: string): string =>
  REPORT_STATUS_LABEL[status as ReportRunStatus] ?? status;

export type ReportStatusTone = "success" | "warning" | "error" | "info";

export const reportStatusTone = (status: string): ReportStatusTone => {
  switch (status) {
    case REPORT_RUN_STATUS.COMPLETED:
      return "success";
    case REPORT_RUN_STATUS.FAILED:
      return "error";
    case REPORT_RUN_STATUS.RUNNING:
      return "info";
    default:
      return "warning";
  }
};

export const SEVERITY_LABEL: Record<ReportSeverity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
};

export const severityLabel = (severity: string): string =>
  SEVERITY_LABEL[severity.toLowerCase() as ReportSeverity] ?? severity;

/** Severity totals as chart rows, most severe first. */
export const severityChartData = (
  totals: Partial<Record<ReportSeverity, number>>,
): { name: string; value: number }[] =>
  REPORT_SEVERITY_ORDER.map((severity) => ({
    name: SEVERITY_LABEL[severity],
    value: Number(totals[severity] ?? 0),
  }));

export const formatBytes = (bytes: number | undefined): string => {
  if (!bytes || bytes <= 0) return "";
  const units = ["B", "KB", "MB", "GB"] as const;
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
};

const ACRONYMS = new Set(["id", "cve", "cwe", "url", "iac", "sca", "sast", "kpi"]);

/** `failed_findings` -> `Failed findings`. */
export const humanizeKey = (key: string): string => {
  const words = key.split(/[_\s]+/).filter(Boolean);
  return words
    .map((word, index) => {
      const lower = word.toLowerCase();
      if (ACRONYMS.has(lower)) return lower.toUpperCase();
      return index === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
    })
    .join(" ");
};

export const formatCell = (value: ReportCellValue | undefined): string => {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") {
    return Number.isInteger(value)
      ? value.toLocaleString("en-US")
      : value.toLocaleString("en-US", { maximumFractionDigits: 1 });
  }
  return value;
};

const KPI_PERCENT_KEYS = /(_pct|_percent|percentage)$/;

export const formatKpi = (key: string, value: ReportCellValue): string => {
  if (typeof value === "number" && KPI_PERCENT_KEYS.test(key)) {
    return `${Math.round(value)}%`;
  }
  return formatCell(value);
};

export type ScoreTone = "good" | "fair" | "poor" | "none";

export const scoreTone = (score: number | null): ScoreTone => {
  if (score === null || Number.isNaN(score)) return "none";
  if (score >= 80) return "good";
  if (score >= 60) return "fair";
  return "poor";
};

export const SCORE_TONE_COLOR: Record<ScoreTone, string> = {
  good: "var(--bg-pass-primary)",
  fair: "var(--bg-warning-primary)",
  poor: "var(--bg-fail-primary)",
  none: "var(--border-neutral-tertiary)",
};

/** Human label for a breakdown row (domain, provider, or policy rows). */
export const sourceRowLabel = (row: ReportSourceRow): string => {
  const label = row.label ?? row.provider ?? row.policy ?? row.name;
  const mode = typeof row.mode === "string" && row.mode ? ` · ${row.mode}` : "";
  return `${formatCell(label ?? "—")}${row.label ? "" : mode}`;
};

const SOURCE_HIDDEN_KEYS = new Set([
  "label",
  "provider",
  "provider_id",
  "provider_type",
  "scan_id",
  "domain",
  "mode",
  "policy",
  "policy_id",
  "name",
  "completed_at",
]);

/** Numeric and short columns worth showing in the per-source table. */
export const sourceColumns = (rows: ReportSourceRow[]): string[] => {
  const keys: string[] = [];
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      if (SOURCE_HIDDEN_KEYS.has(key) || keys.includes(key)) continue;
      keys.push(key);
    }
  }
  return keys.slice(0, 8);
};

const FRAMEWORK_WORDS: Record<string, string> = {
  cis: "CIS",
  nist: "NIST",
  pci: "PCI",
  dss: "DSS",
  iso27001: "ISO 27001",
  soc2: "SOC 2",
  hipaa: "HIPAA",
  gdpr: "GDPR",
  aws: "AWS",
  gcp: "GCP",
  azure: "Azure",
  kubernetes: "Kubernetes",
  m365: "M365",
  github: "GitHub",
  fedramp: "FedRAMP",
  mitre: "MITRE",
  attack: "ATT&CK",
  ens: "ENS",
  rd2022: "RD2022",
};

/** Inherited framework names carry the upstream product name; drop it. */
export const withoutEngineName = (label: string): string =>
  label.replace(/prowler\s*/gi, "").replace(/\s{2,}/g, " ").trim();

/** `cis_2.0_aws` -> `CIS 2.0 AWS`. */
export const frameworkLabel = (complianceId: string): string =>
  withoutEngineName(
  complianceId
    .split("_")
    .filter(Boolean)
    .map(
      (word) =>
        FRAMEWORK_WORDS[word.toLowerCase()] ??
        (/^\d/.test(word) ? word : word.charAt(0).toUpperCase() + word.slice(1)),
    )
    .join(" "),
  );

export const pageCount = (total: number, pageSize: number): number =>
  Math.max(1, Math.ceil(total / pageSize));

export const pageRows = <T>(rows: T[], page: number, pageSize: number): T[] =>
  rows.slice((page - 1) * pageSize, page * pageSize);

export const formatReportDate = (value: string | null | undefined): string => {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};

export const formatReportDay = (value: string | null | undefined): string => {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
};
