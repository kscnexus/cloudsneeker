// Built-in Cloudsneeker product features that the open UI already knows how
// to render. Upstream gates them with `isCloud()`; Cloudsneeker turns them on
// for every deployment and serves matching APIs from `cloudsneeker_api`.
//
// Build order for remaining cloud-gated work (one feature at a time):
// 1. jiraGroupedDispatch (this file / deployment hook)
// 2. advancedScheduling — weekly/monthly/interval schedules API
// 3. findingTriage — status + notes models and API
// 4. crossProviderCompliance — watchlist / across-provider overview
// 5. samlDomains — multi-domain SAML extras
// 6. cloudOrganizations — AWS / Azure / GCP org onboarding
// 7. lighthouseCloudPaths — remaining Seeker AI cloud-only paths

export const CLOUDSNEEKER_FEATURES = {
  alerts: true,
  scanConfiguration: true,
  cliImport: true,
  emailDelivery: true,
  slack: true,
  custodian: true,
  /** Multiple Scans tab: side-by-side compliance comparison between two scans. */
  scanComparison: true,
  /** Send multiple findings or a finding group to Jira in one dispatch. */
  jiraGroupedDispatch: true,
} as const;

export type CloudsneekerFeature = keyof typeof CLOUDSNEEKER_FEATURES;

export const isCloudsneekerFeatureEnabled = (
  feature: CloudsneekerFeature,
): boolean => CLOUDSNEEKER_FEATURES[feature];
