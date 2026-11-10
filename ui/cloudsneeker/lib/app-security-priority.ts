// Risk priority of Application Security findings, set by the API
// (`services/app_security_priority.py`). Priority is not severity: a known
// exploited CVE, a likely exploited CVE or an exposed secret ranks higher.

import {
  RISK_PRIORITIES,
  RISK_PRIORITY,
  type RiskPriority,
} from "@/cloudsneeker/types/area-findings";

interface RiskPriorityInfo {
  /** "P0" */
  code: string;
  /** "Immediate" */
  label: string;
  /** Remediation window in days, counted from first seen. */
  slaDays: number;
  className: string;
}

export const RISK_PRIORITY_INFO: Record<RiskPriority, RiskPriorityInfo> = {
  [RISK_PRIORITY.P0]: {
    code: "P0",
    label: "Immediate",
    slaDays: 2,
    className: "border-bg-data-critical bg-bg-data-critical text-white",
  },
  [RISK_PRIORITY.P1]: {
    code: "P1",
    label: "Urgent",
    slaDays: 7,
    className: "border-bg-data-critical text-text-neutral-primary",
  },
  [RISK_PRIORITY.P2]: {
    code: "P2",
    label: "High",
    slaDays: 30,
    className: "border-bg-data-high text-text-neutral-primary",
  },
  [RISK_PRIORITY.P3]: {
    code: "P3",
    label: "Normal",
    slaDays: 90,
    className: "border-bg-data-medium text-text-neutral-primary",
  },
  [RISK_PRIORITY.P4]: {
    code: "P4",
    label: "Low",
    slaDays: 180,
    className: "border-border-neutral-secondary text-text-neutral-tertiary",
  },
};

/** How the API ranks findings, for help text. */
export const RISK_PRIORITY_RULES =
  "P0: known exploited critical or high CVE, or critical secret. P1: other critical, any known exploited CVE, high CVE with exploit likelihood of 10% or more, or high secret. P2: other high. P3: medium. P4: low.";

export const isRiskPriority = (value: string): value is RiskPriority =>
  (RISK_PRIORITIES as readonly string[]).includes(value);

export const riskPriorityText = (value: string | undefined): string =>
  value && isRiskPriority(value)
    ? `${RISK_PRIORITY_INFO[value].code} ${RISK_PRIORITY_INFO[value].label}`
    : "—";

/** Application posture from its open findings, worst first. */
export const APPLICATION_POSTURE = {
  NOT_SCANNED: "not_scanned",
  CRITICAL: "critical",
  AT_RISK: "at_risk",
  NEEDS_REVIEW: "needs_review",
  HEALTHY: "healthy",
} as const;

export type ApplicationPosture =
  (typeof APPLICATION_POSTURE)[keyof typeof APPLICATION_POSTURE];

export const APPLICATION_POSTURE_LABEL: Record<ApplicationPosture, string> = {
  [APPLICATION_POSTURE.NOT_SCANNED]: "Not scanned",
  [APPLICATION_POSTURE.CRITICAL]: "Critical risk",
  [APPLICATION_POSTURE.AT_RISK]: "At risk",
  [APPLICATION_POSTURE.NEEDS_REVIEW]: "Needs review",
  [APPLICATION_POSTURE.HEALTHY]: "No open findings",
};

/** Critical risk: P0/P1 or critical findings; at risk: high; review: others. */
export const applicationPosture = (
  summary:
    | { total: number; critical: number; high: number; urgent: number }
    | undefined,
): ApplicationPosture => {
  if (!summary) return APPLICATION_POSTURE.NOT_SCANNED;
  if (summary.urgent > 0 || summary.critical > 0) {
    return APPLICATION_POSTURE.CRITICAL;
  }
  if (summary.high > 0) return APPLICATION_POSTURE.AT_RISK;
  if (summary.total > 0) return APPLICATION_POSTURE.NEEDS_REVIEW;
  return APPLICATION_POSTURE.HEALTHY;
};
