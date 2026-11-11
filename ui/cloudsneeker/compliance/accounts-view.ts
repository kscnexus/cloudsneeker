// Multiple Scans has two views: compare two scans, or see every framework
// across the latest scan of each account of one provider type.

import { COMPLIANCE_TAB } from "@/types/compliance";
import { getProviderDisplayName } from "@/types/providers";

import {
  COMPLIANCE_CLOUD_PROVIDERS,
  COMPLIANCE_SAAS_PROVIDERS,
} from "./single-scan-scope";

export const MULTI_SCAN_VIEW_PARAM = "view";
export const PROVIDER_TYPE_PARAM = "providerType";

export const MULTI_SCAN_VIEW = {
  SCANS: "scans",
  ACCOUNTS: "accounts",
} as const;

export type MultiScanView =
  (typeof MULTI_SCAN_VIEW)[keyof typeof MULTI_SCAN_VIEW];

type Params = Record<string, string | string[] | undefined>;

const first = (params: Params, key: string): string | undefined => {
  const value = params[key];
  return Array.isArray(value) ? value[0] : value;
};

export const multiScanViewOf = (params: Params): MultiScanView =>
  first(params, MULTI_SCAN_VIEW_PARAM) === MULTI_SCAN_VIEW.ACCOUNTS
    ? MULTI_SCAN_VIEW.ACCOUNTS
    : MULTI_SCAN_VIEW.SCANS;

const ORDER: readonly string[] = [
  ...COMPLIANCE_CLOUD_PROVIDERS,
  ...COMPLIANCE_SAAS_PROVIDERS,
];

export interface ProviderTypeOption {
  value: string;
  label: string;
  accounts: number;
}

interface ScanWithProvider {
  providerInfo?: { provider?: string; uid?: string };
  relationships?: { provider?: { data?: { id?: string } | null } };
}

/** Provider types with compliance frameworks among the scans, cloud first,
 * with how many accounts of each have a scan. */
export const providerTypeOptions = (
  scans: ScanWithProvider[],
): ProviderTypeOption[] => {
  const accounts = new Map<string, Set<string>>();
  for (const scan of scans) {
    const type = scan.providerInfo?.provider;
    if (!type || !ORDER.includes(type)) continue;
    const account =
      scan.relationships?.provider?.data?.id ?? scan.providerInfo?.uid ?? "";
    const set = accounts.get(type) ?? new Set<string>();
    set.add(account);
    accounts.set(type, set);
  }
  return ORDER.filter((type) => accounts.has(type)).map((type) => ({
    value: type,
    label: getProviderDisplayName(type),
    accounts: accounts.get(type)?.size ?? 0,
  }));
};

/** The provider type asked for, else the first available one. */
export const selectedProviderType = (
  params: Params,
  options: ProviderTypeOption[],
): string | null => {
  const asked = first(params, PROVIDER_TYPE_PARAM);
  if (asked && options.some((option) => option.value === asked)) return asked;
  return options[0]?.value ?? null;
};

/** Link to a Multiple Scans view. */
export const multiScanViewHref = (
  view: MultiScanView,
  providerType?: string | null,
): string => {
  const params = new URLSearchParams({ tab: COMPLIANCE_TAB.CROSS_PROVIDER });
  if (view === MULTI_SCAN_VIEW.ACCOUNTS) {
    params.set(MULTI_SCAN_VIEW_PARAM, MULTI_SCAN_VIEW.ACCOUNTS);
    if (providerType) params.set(PROVIDER_TYPE_PARAM, providerType);
  }
  return `/compliance?${params.toString()}`;
};
