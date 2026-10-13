// Built-in Cloudsneeker product features that the open UI already knows how
// to render. Upstream gates them with `isCloud()`; Cloudsneeker turns them on
// for every deployment and serves matching APIs from `cloudsneeker_api`.

export const CLOUDSNEEKER_FEATURES = {
  alerts: true,
  scanConfiguration: true,
  cliImport: true,
} as const;

export type CloudsneekerFeature = keyof typeof CLOUDSNEEKER_FEATURES;

export const isCloudsneekerFeatureEnabled = (
  feature: CloudsneekerFeature,
): boolean => CLOUDSNEEKER_FEATURES[feature];
