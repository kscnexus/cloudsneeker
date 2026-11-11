// Single Scan compliance: which providers and scans the page offers, and how
// a provider, account and scan choice narrow each other.
//
// Frameworks belong to the provider of a scan (`GET /compliance-overviews`
// per scan), so choosing the provider first and the scan last is what keeps
// the framework list provider-aware. Application Security scans run on the
// `iac` and `image` providers and carry no compliance frameworks; they are
// left out instead of crowding the scan list.

import { COMPLIANCE_TAB } from "@/types/compliance";
import { getProviderDisplayName } from "@/types/providers";

/** Cloud infrastructure providers, listed first. */
export const COMPLIANCE_CLOUD_PROVIDERS = [
  "aws",
  "azure",
  "gcp",
  "kubernetes",
  "oraclecloud",
  "alibabacloud",
  "openstack",
] as const;

/** SaaS and identity posture providers, listed in their own group. */
export const COMPLIANCE_SAAS_PROVIDERS = [
  "m365",
  "googleworkspace",
  "github",
  "mongodbatlas",
  "cloudflare",
  "vercel",
  "okta",
] as const;

export const COMPLIANCE_PROVIDER_TYPES: readonly string[] = [
  ...COMPLIANCE_CLOUD_PROVIDERS,
  ...COMPLIANCE_SAAS_PROVIDERS,
];

const CLOUD = new Set<string>(COMPLIANCE_CLOUD_PROVIDERS);
const ALLOWED = new Set<string>(COMPLIANCE_PROVIDER_TYPES);

/** API filter that keeps code and image scans out of the scan list. */
export const complianceScanFilters = (): Record<string, string> => ({
  "filter[state]": "completed",
  "filter[provider_type__in]": COMPLIANCE_PROVIDER_TYPES.join(","),
});

/** Where the sidebar's Compliance entry lands: Single Scan, the
 * configuration flow (provider, account, scan, frameworks). */
export const SINGLE_SCAN_COMPLIANCE_HREF = `/compliance?tab=${COMPLIANCE_TAB.PER_SCAN}`;

export interface ScopeScan {
  id: string;
  attributes: { completed_at?: string | null; name?: string | null };
  providerInfo: { provider: string; uid: string; alias?: string | null };
  relationships?: { provider?: { data?: { id?: string } | null } };
}

/** Scans that have compliance results to show. */
export const eligibleComplianceScans = <T extends ScopeScan>(
  scans: T[],
  applicationScanIds: ReadonlySet<string> = new Set(),
): T[] =>
  scans.filter(
    (scan) =>
      ALLOWED.has(scan.providerInfo?.provider) &&
      !applicationScanIds.has(scan.id),
  );

const accountKey = (scan: ScopeScan): string =>
  scan.relationships?.provider?.data?.id || scan.providerInfo.uid;

const newestFirst = (left: ScopeScan, right: ScopeScan): number =>
  (right.attributes.completed_at ?? "").localeCompare(
    left.attributes.completed_at ?? "",
  );

export interface ScopeOption {
  value: string;
  label: string;
}

export interface ComplianceScope {
  cloudProviders: ScopeOption[];
  saasProviders: ScopeOption[];
  accounts: ScopeOption[];
  scans: string[];
  providerType: string | null;
  account: string | null;
}

/** Provider, account and scan options around the selected scan. */
export const complianceScope = (
  scans: ScopeScan[],
  selectedScanId: string | null,
): ComplianceScope => {
  const selected = scans.find((scan) => scan.id === selectedScanId) ?? null;
  const providerType = selected?.providerInfo.provider ?? null;
  const account = selected ? accountKey(selected) : null;

  const types = Array.from(
    new Set(scans.map((scan) => scan.providerInfo.provider)),
  );
  const option = (type: string): ScopeOption => ({
    value: type,
    label: getProviderDisplayName(type),
  });
  const ordered = (list: readonly string[]) =>
    list.filter((type) => types.includes(type)).map(option);

  const accounts = new Map<string, ScopeOption>();
  scans
    .filter((scan) => scan.providerInfo.provider === providerType)
    .forEach((scan) => {
      const key = accountKey(scan);
      if (accounts.has(key)) return;
      const alias = scan.providerInfo.alias;
      accounts.set(key, {
        value: key,
        label: alias
          ? `${alias} (${scan.providerInfo.uid})`
          : scan.providerInfo.uid,
      });
    });

  return {
    cloudProviders: ordered(COMPLIANCE_CLOUD_PROVIDERS),
    saasProviders: ordered(COMPLIANCE_SAAS_PROVIDERS),
    accounts: Array.from(accounts.values()).sort((a, b) =>
      a.label.localeCompare(b.label),
    ),
    scans: scans
      .filter((scan) => account !== null && accountKey(scan) === account)
      .sort(newestFirst)
      .map((scan) => scan.id),
    providerType,
    account,
  };
};

/** Newest scan of a provider type (when the type changes). */
export const newestScanOfType = (
  scans: ScopeScan[],
  providerType: string,
): string | null =>
  [...scans]
    .filter((scan) => scan.providerInfo.provider === providerType)
    .sort(newestFirst)[0]?.id ?? null;

/** Newest scan of an account (when the account changes). */
export const newestScanOfAccount = (
  scans: ScopeScan[],
  account: string,
): string | null =>
  [...scans].filter((scan) => accountKey(scan) === account).sort(newestFirst)[0]
    ?.id ?? null;

export const isCloudProviderType = (type: string): boolean => CLOUD.has(type);
