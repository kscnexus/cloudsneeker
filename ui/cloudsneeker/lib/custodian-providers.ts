/** Provider types Cloud Custodian can dry-run in Cloudsneeker. */
export const CUSTODIAN_PROVIDER_TYPES = [
  "aws",
  "azure",
  "gcp",
  "kubernetes",
] as const;

export type CustodianProviderType = (typeof CUSTODIAN_PROVIDER_TYPES)[number];

export const isCustodianProviderType = (
  value: string,
): value is CustodianProviderType =>
  (CUSTODIAN_PROVIDER_TYPES as readonly string[]).includes(value);

export const CUSTODIAN_PROVIDER_FILTER = {
  "filter[provider__in]": CUSTODIAN_PROVIDER_TYPES.join(","),
} as const;
