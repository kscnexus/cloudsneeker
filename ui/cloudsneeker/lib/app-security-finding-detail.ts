// Text for the Application Security finding page: why each category matters
// and how a fix is verified. Verification is always a rescan: a finding is
// closed when the latest scan of its target no longer reports it.

import { SECURITY_CATEGORY_INFO } from "@/cloudsneeker/lib/app-security-categories";
import {
  SECURITY_CATEGORY,
  type SecurityCategory,
} from "@/cloudsneeker/types/area-findings";

export const CATEGORY_IMPACT: Record<SecurityCategory, string> = {
  [SECURITY_CATEGORY.SAST]:
    "Code flaws such as injection or unsafe deserialization can let an attacker read or change data, or run commands, through the application itself.",
  [SECURITY_CATEGORY.SCA]:
    "A vulnerable third-party package is shipped with the application. Public exploits for known CVEs make these a common way in.",
  [SECURITY_CATEGORY.SECRETS]:
    "Anyone with read access to the source, its history or a build log can use an exposed credential. Treat it as compromised until it is rotated.",
  [SECURITY_CATEGORY.IAC]:
    "An insecure infrastructure setting is deployed every time this code runs, for example public storage, open network access or broad permissions.",
  [SECURITY_CATEGORY.CONTAINER]:
    "Every container started from this image carries the weakness, including vulnerable operating system packages or unsafe image settings.",
};

const CATEGORY_STEPS: Record<SecurityCategory, string[]> = {
  [SECURITY_CATEGORY.SAST]: [
    "Fix the code at the reported location and merge the change.",
    "Rescan the static analysis target for the repository.",
  ],
  [SECURITY_CATEGORY.SCA]: [
    "Upgrade the package to the fixed version and update the lock file.",
    "Rescan the repository target.",
  ],
  [SECURITY_CATEGORY.SECRETS]: [
    "Revoke and rotate the credential at its provider first.",
    "Remove it from the code and the git history, then rescan the repository target.",
  ],
  [SECURITY_CATEGORY.IAC]: [
    "Change the setting in the template and apply it.",
    "Rescan the target that holds the template.",
  ],
  [SECURITY_CATEGORY.CONTAINER]: [
    "Rebuild the image on a patched base image or with the fixed package, and push it.",
    "Rescan the image target.",
  ],
};

const CLOSE_STEP =
  "Check that the finding is gone from the latest scan, then set its status to Resolved.";

/** Remediation verification steps for a finding's category. */
export const validationSteps = (category: string | undefined): string[] => [
  ...(category && category in CATEGORY_STEPS
    ? CATEGORY_STEPS[category as SecurityCategory]
    : ["Fix the issue and rescan the target."]),
  CLOSE_STEP,
];

export const categoryImpact = (category: string | undefined): string =>
  category && category in CATEGORY_IMPACT
    ? CATEGORY_IMPACT[category as SecurityCategory]
    : "";

export const categoryLabel = (category: string | undefined): string =>
  category && category in SECURITY_CATEGORY_INFO
    ? SECURITY_CATEGORY_INFO[category as SecurityCategory].label
    : "—";

/** Whole days until (positive) or since (negative) a due date. */
export const daysUntil = (
  due: string | null | undefined,
  now: Date = new Date(),
): number | null => {
  if (!due) return null;
  const time = new Date(due).getTime();
  if (Number.isNaN(time)) return null;
  return Math.ceil((time - now.getTime()) / 86_400_000);
};

export const dueText = (
  due: string | null | undefined,
  overdue: boolean | undefined,
  now: Date = new Date(),
): string => {
  const days = daysUntil(due, now);
  if (days === null) return "No due date";
  if (overdue || days < 0) {
    return `Overdue by ${Math.max(1, -days)} day${-days === 1 ? "" : "s"}`;
  }
  if (days === 0) return "Due today";
  return `Due in ${days} day${days === 1 ? "" : "s"}`;
};
