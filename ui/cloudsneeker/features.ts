// Built-in Cloudsneeker product features that the open UI already knows how
// to render. Upstream gates them with `isCloud()`; Cloudsneeker turns them on
// for every deployment and serves matching APIs from `cloudsneeker_api`.
//
// Build order for remaining cloud-gated work (one feature at a time):
// 1. jiraGroupedDispatch (this file / deployment hook)
// 2. advancedScheduling (in progress) — weekly/monthly/interval schedules API
// 3. findingTriage — status + notes models and API (EB-010, done)
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
  /** Trivy Hub: IaC/image/fs/repo/SBOM/k8s scans into shared Findings. */
  trivy: true,
  /** Report catalog, scheduled reports, and expiring share links (/reports). */
  reports: true,
  /** Multiple Scans tab: side-by-side compliance comparison between two scans. */
  scanComparison: true,
  /** Send multiple findings or a finding group to Jira in one dispatch. */
  jiraGroupedDispatch: true,
  /** Weekly / monthly / interval provider scan schedules via /schedules. */
  advancedScheduling: true,
  /**
   * Saving an edited alert keeps its stored condition when the Findings filter
   * bar has no alert-compatible filters (API-created or advanced rules).
   * Permission errors still block the save.
   */
  alertEditKeepsStoredCondition: true,
  /**
   * Finding triage status and notes (EB-010): the inherited triage column,
   * drawer control and notes call `cloudsneeker_api` finding-triages.
   */
  findingTriage: true,
} as const;

export type CloudsneekerFeature = keyof typeof CLOUDSNEEKER_FEATURES;

export const isCloudsneekerFeatureEnabled = (
  feature: CloudsneekerFeature,
): boolean => CLOUDSNEEKER_FEATURES[feature];
