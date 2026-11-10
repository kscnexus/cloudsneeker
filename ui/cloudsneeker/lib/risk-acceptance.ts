// Risk acceptance (EB-019): reason and expiry sent with the `risk_accepted`
// triage status. Limits match `cloudsneeker_api.services.finding_triage`.

export const RISK_DEFAULT_DAYS = 90;
export const RISK_MAX_DAYS = 365;
export const RISK_REASON_MAX_LENGTH = 1000;
export const RISK_ACCEPTED_STATUS = "risk_accepted" as const;

export interface RiskAcceptanceInput {
  risk_reason: string;
  /** `YYYY-MM-DD`. */
  risk_expires_on: string;
}

/** `YYYY-MM-DD` of `today` plus `days`, in UTC (the API compares UTC dates). */
export const isoDateAfter = (
  days: number,
  today: Date = new Date(),
): string => {
  const date = new Date(
    Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()),
  );
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
};

export const defaultRiskAcceptance = (
  today: Date = new Date(),
): RiskAcceptanceInput => ({
  risk_reason: "",
  risk_expires_on: isoDateAfter(RISK_DEFAULT_DAYS, today),
});

/** Why the form cannot be sent yet, or null when it can. */
export const riskAcceptanceProblem = (
  input: RiskAcceptanceInput,
  today: Date = new Date(),
): string | null => {
  if (!input.risk_reason.trim()) return "Give a reason for accepting the risk.";
  if (!/^\d{4}-\d{2}-\d{2}$/.test(input.risk_expires_on)) {
    return "Choose an expiry date.";
  }
  if (input.risk_expires_on < isoDateAfter(1, today)) {
    return "The expiry date must be after today.";
  }
  if (input.risk_expires_on > isoDateAfter(RISK_MAX_DAYS, today)) {
    return `A risk can be accepted for at most ${RISK_MAX_DAYS} days.`;
  }
  return null;
};

/** Days until an accepted risk expires (negative once it has passed). */
export const daysUntil = (
  isoDate: string,
  today: Date = new Date(),
): number => {
  const start = Date.UTC(
    today.getUTCFullYear(),
    today.getUTCMonth(),
    today.getUTCDate(),
  );
  const end = Date.parse(`${isoDate}T00:00:00Z`);
  return Math.round((end - start) / 86_400_000);
};
