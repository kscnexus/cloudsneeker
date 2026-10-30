// Plan helpers shared by the tenant app (navigation, banner, profile card)
// and the operator console. Pure functions so they are unit tested.

import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import {
  type EntitlementsAttributes,
  PLAN_FEATURE,
  PLAN_LIMIT,
  type PlanFeature,
  type PlanLimit,
  type PlanLimits,
  SUBSCRIPTION_STATUS,
  type SubscriptionStatus,
  type UsageCounts,
} from "@/cloudsneeker/types/operator";

export const PLAN_FEATURE_LABEL: Record<PlanFeature, string> = {
  cloud_posture: "Cloud posture",
  attack_paths: "Attack paths",
  compliance: "Compliance",
  application_security: "Application security",
  sast: "Static code analysis",
  governance: "Governance",
  reports: "Reports",
  report_schedules: "Scheduled reports",
  seeker_ai: "Assistant",
  finding_triage: "Finding triage",
  audit_log: "Audit log",
  sso: "Single sign-on",
  api_access: "API access",
  integrations: "Integrations",
};

export const PLAN_LIMIT_LABEL: Record<PlanLimit, string> = {
  providers: "Providers",
  users: "Users",
  application_security_targets: "Application security targets",
  scans_per_month: "Scans per month",
  report_schedules: "Report schedules",
  seeker_ai_requests_per_month: "Assistant requests per month",
};

/** Usage key the API reports for each limit. */
export const LIMIT_USAGE_KEY: Record<PlanLimit, string> = {
  providers: "providers",
  users: "users",
  application_security_targets: "application_security_targets",
  scans_per_month: "scans_this_month",
  report_schedules: "report_schedules",
  seeker_ai_requests_per_month: "seeker_ai_requests_this_month",
};

export const SUBSCRIPTION_STATUS_LABEL: Record<SubscriptionStatus, string> = {
  trial: "Trial",
  active: "Active",
  past_due: "Past due",
  suspended: "Suspended",
  expired: "Expired",
  cancelled: "Cancelled",
};

export const PLAN_FEATURES = Object.values(PLAN_FEATURE);
export const PLAN_LIMITS = Object.values(PLAN_LIMIT);

/** Statuses where the organization is read-only. */
export const READ_ONLY_STATUSES: readonly SubscriptionStatus[] = [
  SUBSCRIPTION_STATUS.SUSPENDED,
  SUBSCRIPTION_STATUS.EXPIRED,
  SUBSCRIPTION_STATUS.CANCELLED,
];

export const TRIAL_WARNING_DAYS = 7;

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Sidebar paths that belong to a plan feature. A link whose path equals or
 * starts with one of these is hidden when the plan does not include it.
 */
export const NAVIGATION_FEATURE_PATHS: readonly {
  path: string;
  feature: PlanFeature;
}[] = [
  { path: "/attack-paths", feature: PLAN_FEATURE.ATTACK_PATHS },
  { path: "/compliance", feature: PLAN_FEATURE.COMPLIANCE },
  {
    path: PRODUCT_ROUTE.APPLICATION_SECURITY,
    feature: PLAN_FEATURE.APPLICATION_SECURITY,
  },
  { path: PRODUCT_ROUTE.GOVERNANCE, feature: PLAN_FEATURE.GOVERNANCE },
  { path: PRODUCT_ROUTE.REPORTS, feature: PLAN_FEATURE.REPORTS },
  { path: PRODUCT_ROUTE.FINDING_TRIAGE, feature: PLAN_FEATURE.FINDING_TRIAGE },
  { path: PRODUCT_ROUTE.AUDIT_LOG, feature: PLAN_FEATURE.AUDIT_LOG },
  { path: "/lighthouse", feature: PLAN_FEATURE.SEEKER_AI },
  { path: "/integrations", feature: PLAN_FEATURE.INTEGRATIONS },
];

const pathOf = (href: string): string => href.split("?")[0] ?? href;

/** Feature that gates a sidebar link, if any. */
export const featureForHref = (href: string): PlanFeature | null => {
  const path = pathOf(href);
  const match = NAVIGATION_FEATURE_PATHS.find(
    (entry) => path === entry.path || path.startsWith(`${entry.path}/`),
  );
  return match ? match.feature : null;
};

/**
 * Whether a link is in the plan. `features === null` means the entitlements
 * are not known yet (or failed to load): everything stays visible.
 */
export const isHrefInPlan = (
  href: string,
  features: readonly string[] | null,
): boolean => {
  if (features === null) return true;
  const feature = featureForHref(href);
  return feature === null || features.includes(feature);
};

const parseTime = (value: string | null | undefined): number | null => {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : null;
};

/** Whole days from `now` until `value` (negative when past), or `null`. */
export const daysUntil = (
  value: string | null | undefined,
  now: Date = new Date(),
): number | null => {
  const time = parseTime(value);
  if (time === null) return null;
  return Math.ceil((time - now.getTime()) / DAY_MS);
};

export const formatPlanDate = (value: string | null | undefined): string => {
  const time = parseTime(value);
  if (time === null) return "No end date";
  return new Date(time).toLocaleDateString("en-GB", {
    day: "numeric",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  });
};

export const SUBSCRIPTION_BANNER_TONE = {
  DANGER: "danger",
  WARNING: "warning",
} as const;

export type SubscriptionBannerTone =
  (typeof SUBSCRIPTION_BANNER_TONE)[keyof typeof SUBSCRIPTION_BANNER_TONE];

export interface SubscriptionBannerContent {
  tone: SubscriptionBannerTone;
  title: string;
  message: string;
}

/**
 * Banner for a read-only subscription, or a trial (or plan) ending within
 * `TRIAL_WARNING_DAYS`. `null` when nothing needs saying.
 */
export const subscriptionBanner = (
  entitlements: Pick<
    EntitlementsAttributes,
    "effective_status" | "read_only" | "trial_ends_at" | "ends_at" | "plan"
  >,
  now: Date = new Date(),
): SubscriptionBannerContent | null => {
  const status = entitlements.effective_status;
  if (entitlements.read_only || READ_ONLY_STATUSES.includes(status)) {
    const label = SUBSCRIPTION_STATUS_LABEL[status] ?? "inactive";
    return {
      tone: SUBSCRIPTION_BANNER_TONE.DANGER,
      title: `Subscription ${label.toLowerCase()}`,
      message:
        "You can sign in and view your data, but changes are turned off until the subscription is renewed. Contact your account manager.",
    };
  }
  const end =
    status === SUBSCRIPTION_STATUS.TRIAL
      ? (entitlements.trial_ends_at ?? entitlements.ends_at)
      : entitlements.ends_at;
  const days = daysUntil(end, now);
  if (days === null || days < 0 || days > TRIAL_WARNING_DAYS) return null;
  const when =
    days <= 0 ? "today" : days === 1 ? "in 1 day" : `in ${days} days`;
  const what =
    status === SUBSCRIPTION_STATUS.TRIAL
      ? "Your trial"
      : `Your ${entitlements.plan.name} plan`;
  return {
    tone: SUBSCRIPTION_BANNER_TONE.WARNING,
    title: `${what} ends ${when}`,
    message: `It ends on ${formatPlanDate(end)}. After that the organization becomes read-only.`,
  };
};

export interface LimitUsage {
  key: PlanLimit;
  label: string;
  used: number | null;
  limit: number | null;
  /** 0..1 of the limit, `null` when unlimited or not tracked. */
  ratio: number | null;
  over: boolean;
}

/** One row per limit: usage against the limit, for usage bars. */
export const limitUsageRows = (
  usage: UsageCounts,
  limits: PlanLimits,
): LimitUsage[] =>
  PLAN_LIMITS.map((key) => {
    const rawUsed = usage[LIMIT_USAGE_KEY[key]];
    const used = typeof rawUsed === "number" ? rawUsed : null;
    const rawLimit = limits[key];
    const limit = typeof rawLimit === "number" ? rawLimit : null;
    const ratio =
      used === null || limit === null
        ? null
        : limit === 0
          ? used > 0
            ? 1
            : 0
          : Math.min(1, used / limit);
    return {
      key,
      label: PLAN_LIMIT_LABEL[key],
      used,
      limit,
      ratio,
      over: used !== null && limit !== null && used > limit,
    };
  });

export const formatLimit = (limit: number | null | undefined): string =>
  typeof limit === "number" ? limit.toLocaleString("en-GB") : "Unlimited";
