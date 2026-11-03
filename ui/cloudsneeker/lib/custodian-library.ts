// Filters, coverage and hrefs for the governance policy library page. The
// library data itself comes from the API (`/custodian-library`).

import { governanceHref } from "@/cloudsneeker/routes";
import {
  LIBRARY_PROVIDER,
  LIBRARY_SEVERITY,
  type LibraryCoverageRow,
  type LibraryPolicyAttributes,
  type LibraryProvider,
  type LibrarySeverity,
  type PolicyDraftAttributes,
  type PolicyValidationAttributes,
} from "@/cloudsneeker/types/custodian-library";

export const LIBRARY_PROVIDER_LABEL: Record<LibraryProvider, string> = {
  [LIBRARY_PROVIDER.AWS]: "AWS",
  [LIBRARY_PROVIDER.AZURE]: "Azure",
  [LIBRARY_PROVIDER.GCP]: "Google Cloud",
};

export const LIBRARY_PROVIDERS = Object.values(LIBRARY_PROVIDER);

export const LIBRARY_SEVERITIES = Object.values(LIBRARY_SEVERITY);

const SEVERITY_RANK: Record<LibrarySeverity, number> = {
  [LIBRARY_SEVERITY.CRITICAL]: 0,
  [LIBRARY_SEVERITY.HIGH]: 1,
  [LIBRARY_SEVERITY.MEDIUM]: 2,
  [LIBRARY_SEVERITY.LOW]: 3,
};

export const isLibraryProvider = (
  value: string | undefined,
): value is LibraryProvider =>
  (LIBRARY_PROVIDERS as readonly string[]).includes(value ?? "");

export const libraryProviderFromParam = (
  value: string | string[] | undefined,
): LibraryProvider => {
  const raw = Array.isArray(value) ? value[0] : value;
  return isLibraryProvider(raw) ? raw : LIBRARY_PROVIDER.AWS;
};

export const libraryHref = (providerType?: LibraryProvider): string =>
  providerType
    ? `${governanceHref("library")}?provider=${providerType}`
    : governanceHref("library");

export const generateHref = (): string => governanceHref("generate");

export interface LibraryFilters {
  search: string;
  category: string;
  severity: string;
  starterOnly: boolean;
  hideInstalled: boolean;
}

export const EMPTY_LIBRARY_FILTERS: LibraryFilters = {
  search: "",
  category: "",
  severity: "",
  starterOnly: false,
  hideInstalled: false,
};

const searchText = (policy: LibraryPolicyAttributes): string =>
  [
    policy.name,
    policy.description,
    policy.resource,
    policy.category_name,
    ...policy.frameworks,
  ]
    .join(" ")
    .toLowerCase();

/** Apply the page filters and sort by severity, then name. */
export const filterLibraryPolicies = (
  policies: LibraryPolicyAttributes[],
  filters: LibraryFilters,
): LibraryPolicyAttributes[] => {
  const terms = filters.search.toLowerCase().split(/\s+/).filter(Boolean);
  return policies
    .filter(
      (policy) => !filters.category || policy.category === filters.category,
    )
    .filter(
      (policy) => !filters.severity || policy.severity === filters.severity,
    )
    .filter((policy) => !filters.starterOnly || policy.starter)
    .filter((policy) => !filters.hideInstalled || !policy.installed)
    .filter((policy) => {
      if (terms.length === 0) return true;
      const text = searchText(policy);
      return terms.every((term) => text.includes(term));
    })
    .sort(
      (a, b) =>
        SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
        a.name.localeCompare(b.name),
    );
};

/** Starter policies not yet in the workspace. */
export const pendingStarterIds = (
  policies: LibraryPolicyAttributes[],
): string[] =>
  policies
    .filter((policy) => policy.starter && !policy.installed)
    .map((policy) => policy.id);

export interface CoverageSummary {
  rows: LibraryCoverageRow[];
  active: number;
  total: number;
  coveredCategories: number;
}

export const summarizeCoverage = (
  rows: LibraryCoverageRow[],
  providerType: LibraryProvider,
): CoverageSummary => {
  const providerRows = rows.filter((row) => row.provider_type === providerType);
  return {
    rows: providerRows,
    active: providerRows.reduce((sum, row) => sum + row.active, 0),
    total: providerRows.reduce((sum, row) => sum + row.total, 0),
    coveredCategories: providerRows.filter((row) => row.active > 0).length,
  };
};

export const coveragePercent = (active: number, total: number): number =>
  total > 0 ? Math.round((active / total) * 100) : 0;

export interface InstallResult {
  created: number;
  skipped: string[];
}

/** Read the created/skipped counts from an install response. */
export const readInstallResult = (response: unknown): InstallResult | null => {
  if (!response || typeof response !== "object") return null;
  const meta = (response as { meta?: Partial<InstallResult> }).meta;
  if (!meta || typeof meta.created !== "number") return null;
  return {
    created: meta.created,
    skipped: Array.isArray(meta.skipped) ? meta.skipped : [],
  };
};

export const installMessage = ({ created, skipped }: InstallResult): string => {
  const added =
    created === 1 ? "Added 1 policy." : `Added ${created} policies.`;
  if (skipped.length === 0) return added;
  const already =
    skipped.length === 1
      ? "1 was already on this provider."
      : `${skipped.length} were already on this provider.`;
  return created === 0 ? `Nothing added: ${already}` : `${added} ${already}`;
};

/** Error text from a server action result, if it failed. */
export const actionError = (response: unknown): string | null => {
  if (!response || typeof response !== "object") {
    return "Something went wrong. Try again.";
  }
  const error = (response as { error?: unknown }).error;
  return typeof error === "string" && error ? error : null;
};

/** Starting points shown under the plain-language prompt. */
export const GENERATE_EXAMPLES: Record<LibraryProvider, string[]> = {
  [LIBRARY_PROVIDER.AWS]: [
    "EC2 instances in production without a Backup tag",
    "Lambda functions with more than 3 GB of memory",
    "S3 buckets without object lock",
  ],
  [LIBRARY_PROVIDER.AZURE]: [
    "Virtual machines larger than 8 vCPUs without an Owner tag",
    "Storage accounts that allow public network access",
    "Key vaults without soft delete",
  ],
  [LIBRARY_PROVIDER.GCP]: [
    "Compute instances without a team label",
    "Cloud SQL instances not on PostgreSQL 15 or later",
    "Buckets in a region outside Europe",
  ],
};

const attributesOf = <T>(response: unknown): T | null => {
  if (!response || typeof response !== "object") return null;
  const data = (response as { data?: { attributes?: T } }).data;
  return data?.attributes ?? null;
};

export const readDraft = (response: unknown): PolicyDraftAttributes | null => {
  const draft = attributesOf<PolicyDraftAttributes>(response);
  return draft && typeof draft.policy_yaml === "string" ? draft : null;
};

export const readValidation = (
  response: unknown,
): PolicyValidationAttributes | null => {
  const result = attributesOf<PolicyValidationAttributes>(response);
  return result && typeof result.valid === "boolean" ? result : null;
};

/** Human-readable policy name from the draft slug, or the prompt. */
export const draftName = (slug: string, prompt: string): string => {
  const words = (slug || prompt)
    .replace(/[-_]+/g, " ")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (words.length === 0) return "";
  const text = words.join(" ");
  return (text.charAt(0).toUpperCase() + text.slice(1)).slice(0, 100);
};
