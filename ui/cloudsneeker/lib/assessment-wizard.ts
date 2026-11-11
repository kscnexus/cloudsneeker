// Security assessment wizard: report types, scope, period, sections, and the
// API payload. The API validates every value again (`reports/catalog.py`).

import {
  REPORT_FORMAT,
  REPORT_TYPE_ID,
  type ReportParams,
  type ReportRunAttributes,
  type SelectableReportFormat,
} from "@/cloudsneeker/types/reports";

import type { ReportRunPayload } from "./report-form-schema";

export const ASSESSMENT_TYPE_IDS = [
  REPORT_TYPE_ID.SECURITY_ASSESSMENT,
  REPORT_TYPE_ID.APPSEC_ASSESSMENT,
  REPORT_TYPE_ID.CLOUD_ASSESSMENT,
  REPORT_TYPE_ID.GOVERNANCE_ASSESSMENT,
] as const;

export type AssessmentTypeId = (typeof ASSESSMENT_TYPE_IDS)[number];

export const isAssessmentType = (id: string): id is AssessmentTypeId =>
  (ASSESSMENT_TYPE_IDS as readonly string[]).includes(id);

export const WIZARD_STEP = {
  TYPE: "type",
  SCOPE: "scope",
  PERIOD: "period",
  SECTIONS: "sections",
  GENERATE: "generate",
} as const;

export type WizardStep = (typeof WIZARD_STEP)[keyof typeof WIZARD_STEP];

export const WIZARD_STEPS: { id: WizardStep; label: string }[] = [
  { id: WIZARD_STEP.TYPE, label: "Report type" },
  { id: WIZARD_STEP.SCOPE, label: "Scope" },
  { id: WIZARD_STEP.PERIOD, label: "Period" },
  { id: WIZARD_STEP.SECTIONS, label: "Sections" },
  { id: WIZARD_STEP.GENERATE, label: "Generate" },
];

export const ASSESSMENT_PERIOD = {
  LATEST: "latest",
  DAYS_7: "7d",
  DAYS_30: "30d",
  DAYS_90: "90d",
  CUSTOM: "custom",
} as const;

export type AssessmentPeriod =
  (typeof ASSESSMENT_PERIOD)[keyof typeof ASSESSMENT_PERIOD];

export const PERIOD_OPTIONS: {
  id: AssessmentPeriod;
  label: string;
  hint: string;
}[] = [
  {
    id: ASSESSMENT_PERIOD.LATEST,
    label: "Latest results",
    hint: "Newest result of every source, whatever its age. Stale sources are flagged.",
  },
  {
    id: ASSESSMENT_PERIOD.DAYS_7,
    label: "Last 7 days",
    hint: "Only sources assessed in the last 7 days.",
  },
  {
    id: ASSESSMENT_PERIOD.DAYS_30,
    label: "Last 30 days",
    hint: "Only sources assessed in the last 30 days.",
  },
  {
    id: ASSESSMENT_PERIOD.DAYS_90,
    label: "Last 90 days",
    hint: "Only sources assessed in the last 90 days.",
  },
  {
    id: ASSESSMENT_PERIOD.CUSTOM,
    label: "Custom range",
    hint: "Pick a start and an end date.",
  },
];

export const ASSESSMENT_SECTION = {
  TREND: "trend",
  TOP_RISKS: "top_risks",
  POSTURE: "posture",
  COMPLIANCE: "compliance",
  ROADMAP: "roadmap",
  APPENDIX: "appendix",
  AI_INSIGHTS: "ai_insights",
} as const;

export type AssessmentSection =
  (typeof ASSESSMENT_SECTION)[keyof typeof ASSESSMENT_SECTION];

export const SECTION_LABELS: Record<
  AssessmentSection,
  { label: string; hint: string }
> = {
  [ASSESSMENT_SECTION.TREND]: {
    label: "Trend",
    hint: "Open findings over the period, like-for-like coverage only.",
  },
  [ASSESSMENT_SECTION.TOP_RISKS]: {
    label: "Top risks",
    hint: "Up to ten issues with business impact and full fix guidance.",
  },
  [ASSESSMENT_SECTION.POSTURE]: {
    label: "Posture pages",
    hint: "One page per area with categories and leading issues.",
  },
  [ASSESSMENT_SECTION.COMPLIANCE]: {
    label: "Compliance",
    hint: "Assessed frameworks, never presented as certification.",
  },
  [ASSESSMENT_SECTION.ROADMAP]: {
    label: "Remediation roadmap",
    hint: "0-24h, 1-7d, 8-30d, and 31-90d windows with owners and SLAs.",
  },
  [ASSESSMENT_SECTION.APPENDIX]: {
    label: "Technical appendix",
    hint: "Every open finding by category and severity.",
  },
  [ASSESSMENT_SECTION.AI_INSIGHTS]: {
    label: "Seeker AI insights",
    hint: "Optional. Cited interpretation, kept apart from scanner facts.",
  },
};

/** Areas a report reads; drives which sources the scope step offers. */
const TYPE_AREAS: Record<
  AssessmentTypeId,
  readonly ("cloud" | "appsec" | "governance")[]
> = {
  [REPORT_TYPE_ID.SECURITY_ASSESSMENT]: ["cloud", "appsec", "governance"],
  [REPORT_TYPE_ID.APPSEC_ASSESSMENT]: ["appsec"],
  [REPORT_TYPE_ID.CLOUD_ASSESSMENT]: ["cloud"],
  [REPORT_TYPE_ID.GOVERNANCE_ASSESSMENT]: ["governance"],
};

const TYPE_SECTIONS: Record<AssessmentTypeId, readonly AssessmentSection[]> = {
  [REPORT_TYPE_ID.SECURITY_ASSESSMENT]: Object.values(ASSESSMENT_SECTION),
  [REPORT_TYPE_ID.APPSEC_ASSESSMENT]: Object.values(ASSESSMENT_SECTION).filter(
    (section) => section !== ASSESSMENT_SECTION.COMPLIANCE,
  ),
  [REPORT_TYPE_ID.CLOUD_ASSESSMENT]: Object.values(ASSESSMENT_SECTION).filter(
    (section) => section !== ASSESSMENT_SECTION.COMPLIANCE,
  ),
  [REPORT_TYPE_ID.GOVERNANCE_ASSESSMENT]: Object.values(ASSESSMENT_SECTION),
};

/** Sections the report type offers. */
export const sectionsFor = (type: AssessmentTypeId): AssessmentSection[] => [
  ...TYPE_SECTIONS[type],
];

/** Sections on by default (AI is opt-in). */
export const defaultSections = (type: AssessmentTypeId): AssessmentSection[] =>
  sectionsFor(type).filter(
    (section) => section !== ASSESSMENT_SECTION.AI_INSIGHTS,
  );

export const supportsFrameworks = (type: AssessmentTypeId): boolean =>
  type === REPORT_TYPE_ID.SECURITY_ASSESSMENT ||
  type === REPORT_TYPE_ID.GOVERNANCE_ASSESSMENT;

const APPSEC_PROVIDER_TYPES = new Set(["iac", "image", "kubernetes"]);

export interface ScopeSource {
  id: string;
  label: string;
  providerType: string;
}

interface ProviderLike {
  id: string;
  attributes: { provider?: string; alias?: string | null; uid?: string };
}

export const scopeSources = (providers: ProviderLike[]): ScopeSource[] =>
  providers.map((provider) => ({
    id: provider.id,
    label: provider.attributes.alias || provider.attributes.uid || provider.id,
    providerType: provider.attributes.provider ?? "",
  }));

/** Sources relevant to a report type (cloud accounts, code targets, or both). */
export const sourcesFor = (
  type: AssessmentTypeId,
  sources: ScopeSource[],
): ScopeSource[] => {
  const areas = TYPE_AREAS[type];
  return sources.filter((source) => {
    const appsec = APPSEC_PROVIDER_TYPES.has(source.providerType);
    if (areas.includes("appsec") && appsec) return true;
    if ((areas.includes("cloud") || areas.includes("governance")) && !appsec) {
      return true;
    }
    // Kubernetes clusters are both a cloud and an application source.
    return source.providerType === "kubernetes" && areas.includes("cloud");
  });
};

export interface WizardState {
  reportType: AssessmentTypeId;
  providerIds: string[];
  frameworks: string[];
  period: AssessmentPeriod;
  dateFrom: string;
  dateTo: string;
  sections: AssessmentSection[];
  staleDays: number;
  formats: SelectableReportFormat[];
}

export const initialWizardState = (
  type: AssessmentTypeId = REPORT_TYPE_ID.SECURITY_ASSESSMENT,
): WizardState => ({
  reportType: type,
  providerIds: [],
  frameworks: [],
  period: ASSESSMENT_PERIOD.DAYS_30,
  dateFrom: "",
  dateTo: "",
  sections: defaultSections(type),
  staleDays: 7,
  formats: [REPORT_FORMAT.PDF, REPORT_FORMAT.CSV],
});

/** Switching type resets what the new type does not offer. */
export const withReportType = (
  state: WizardState,
  type: AssessmentTypeId,
): WizardState => ({
  ...state,
  reportType: type,
  providerIds: [],
  frameworks: supportsFrameworks(type) ? state.frameworks : [],
  sections: defaultSections(type),
});

/** Validation message of a step, or ``null`` when it may be left. */
export const stepError = (
  step: WizardStep,
  state: WizardState,
): string | null => {
  if (
    step === WIZARD_STEP.PERIOD &&
    state.period === ASSESSMENT_PERIOD.CUSTOM
  ) {
    if (!state.dateFrom && !state.dateTo) {
      return "Pick a start date, an end date, or both.";
    }
    if (state.dateFrom && state.dateTo && state.dateFrom > state.dateTo) {
      return "The start date must be before the end date.";
    }
  }
  if (step === WIZARD_STEP.GENERATE && state.formats.length === 0) {
    return "Pick at least one file format.";
  }
  if (
    step === WIZARD_STEP.SCOPE &&
    (state.staleDays < 1 || state.staleDays > 90)
  ) {
    return "Stale after must be between 1 and 90 days.";
  }
  return null;
};

/** API payload for the report run. */
export const buildAssessmentPayload = (
  state: WizardState,
): ReportRunPayload => {
  const params: ReportParams = {
    provider_ids: state.providerIds,
    period: state.period,
    sections: state.sections.filter((section) =>
      sectionsFor(state.reportType).includes(section),
    ),
    stale_days: state.staleDays,
  };
  if (state.period === ASSESSMENT_PERIOD.CUSTOM) {
    if (state.dateFrom) params.date_from = state.dateFrom;
    if (state.dateTo) params.date_to = state.dateTo;
  }
  if (supportsFrameworks(state.reportType) && state.frameworks.length > 0) {
    params.frameworks = state.frameworks;
  }
  return { reportType: state.reportType, params, formats: state.formats };
};

export const QUALITY_STATUS = {
  PASS: "pass",
  WARN: "warn",
  FAIL: "fail",
} as const;

export type QualityStatus =
  (typeof QUALITY_STATUS)[keyof typeof QUALITY_STATUS];

export interface AssessmentRunSummary {
  period: string | null;
  scope: string[];
  version: string | null;
  warnings: string[];
  qualityStatus: QualityStatus | null;
  distributable: boolean | null;
  qualitySummary: string | null;
  failedChecks: string[];
  grade: string | null;
  score: number | null;
  pages: number | null;
}

const asString = (value: unknown): string | null =>
  typeof value === "string" && value ? value : null;

const asStrings = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];

/** Readable fields of a run's stored summary (missing values are ``null``). */
export const assessmentSummary = (
  attributes: Pick<ReportRunAttributes, "summary">,
): AssessmentRunSummary => {
  const summary = (attributes.summary ?? {}) as Record<string, unknown>;
  const quality = (summary.quality ?? {}) as Record<string, unknown>;
  const status = asString(quality.status);
  return {
    period: asString(summary.period),
    scope: asStrings(summary.scope),
    version: asString(summary.engine_version),
    warnings: asStrings(summary.warnings),
    qualityStatus:
      status && (Object.values(QUALITY_STATUS) as string[]).includes(status)
        ? (status as QualityStatus)
        : null,
    distributable:
      typeof quality.distributable === "boolean" ? quality.distributable : null,
    qualitySummary: asString(quality.summary),
    failedChecks: asStrings(quality.failed),
    grade: asString(summary.grade),
    score: typeof summary.score === "number" ? summary.score : null,
    pages: typeof summary.pages === "number" ? summary.pages : null,
  };
};

/** Short scope text for the history table. */
export const scopeLabel = (
  summary: AssessmentRunSummary,
  providerCount: number,
): string => {
  if (summary.scope.length === 0) {
    return providerCount
      ? `${providerCount} selected source(s)`
      : "All visible sources";
  }
  const shown = summary.scope.slice(0, 2).join(", ");
  const more = summary.scope.length - 2;
  return more > 0 ? `${shown} +${more}` : shown;
};

export const qualityLabel = (summary: AssessmentRunSummary): string => {
  if (summary.distributable === null) return "Not checked";
  if (!summary.distributable) return "Not distributable";
  return summary.qualityStatus === QUALITY_STATUS.WARN
    ? "Distributable, with warnings"
    : "Distributable";
};
