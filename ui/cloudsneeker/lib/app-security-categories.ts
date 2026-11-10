// Security categories of Application Security findings. The API puts every
// finding in exactly one category (`services/app_security_categories.py`), so
// the category counts add up to the finding total. Severity, triage status
// and source are separate dimensions.

import {
  SECURITY_CATEGORIES,
  SECURITY_CATEGORY,
  type SecurityCategory,
} from "@/cloudsneeker/types/area-findings";

interface SecurityCategoryInfo {
  label: string;
  /** Short name for chips and table cells. */
  short: string;
  description: string;
}

export const SECURITY_CATEGORY_INFO: Record<
  SecurityCategory,
  SecurityCategoryInfo
> = {
  [SECURITY_CATEGORY.SAST]: {
    label: "Static analysis (SAST)",
    short: "SAST",
    description:
      "Vulnerable source code: injection, unsafe deserialization, weak crypto.",
  },
  [SECURITY_CATEGORY.SCA]: {
    label: "Open source dependencies (SCA)",
    short: "SCA",
    description: "Known vulnerable or license-restricted third-party packages.",
  },
  [SECURITY_CATEGORY.SECRETS]: {
    label: "Secrets",
    short: "Secrets",
    description: "Credentials, keys and tokens committed to source.",
  },
  [SECURITY_CATEGORY.IAC]: {
    label: "Infrastructure as code (IaC)",
    short: "IaC",
    description: "Insecure Terraform, CloudFormation and Kubernetes settings.",
  },
  [SECURITY_CATEGORY.CONTAINER]: {
    label: "Container images",
    short: "Container",
    description: "Vulnerable OS and app packages and insecure image settings.",
  },
};

/** Testing types the product does not run; shown as not integrated. */
export const NOT_INTEGRATED_CATEGORIES = [
  "Dynamic testing (DAST)",
  "API security testing",
] as const;

export const isSecurityCategory = (value: string): value is SecurityCategory =>
  (SECURITY_CATEGORIES as readonly string[]).includes(value);

export const securityCategoryShort = (value: string | undefined): string =>
  value && isSecurityCategory(value)
    ? SECURITY_CATEGORY_INFO[value].short
    : "—";

export interface SecurityCategoryTab {
  category: SecurityCategory;
  label: string;
  count: number;
  /** A target is set up to report it, or it already has findings. */
  enabled: boolean;
}

/** One tab per category with its count, in a fixed order. */
export const securityCategoryTabs = (
  counts: Partial<Record<string, number>> | undefined,
  enabled: readonly string[] | undefined,
): SecurityCategoryTab[] =>
  SECURITY_CATEGORIES.map((category) => {
    const count = counts?.[category] ?? 0;
    return {
      category,
      label: SECURITY_CATEGORY_INFO[category].short,
      count,
      enabled: count > 0 || Boolean(enabled?.includes(category)),
    };
  });

/** Total across categories: the finding count without a category filter. */
export const categoryTotal = (tabs: readonly SecurityCategoryTab[]): number =>
  tabs.reduce((sum, tab) => sum + tab.count, 0);
