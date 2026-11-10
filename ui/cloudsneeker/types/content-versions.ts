// Types for `GET /content-versions` (EB-048). Keys match
// `cloudsneeker_api.services.content_versions.content_versions`.

export const VULN_DB_STATUS = {
  FRESH: "fresh",
  STALE: "stale",
  MISSING: "missing",
  NOT_CONFIGURED: "not_configured",
} as const;

export type VulnDbStatus = (typeof VULN_DB_STATUS)[keyof typeof VULN_DB_STATUS];

export interface VulnerabilityDatabaseVersion {
  status: VulnDbStatus;
  refreshed_at: string | null;
  /** When the publisher built this copy of the database. */
  published_at: string | null;
  age_hours: number | null;
  max_age_hours: number;
  java_db: boolean;
}

export interface EngineVersion {
  id: string;
  label: string;
  version: string | null;
}

/** One exploit intelligence feed (EPSS or CISA KEV, EB-022). */
export interface ExploitIntelligenceFeed {
  id: string;
  label: string;
  /** Day scored (EPSS) or catalog version (KEV). */
  version: string | null;
  records: number | null;
  refreshed_at: string | null;
  last_error: string | null;
}

export interface ContentVersionsAttributes {
  release: string | null;
  cloud_security: { version: string; checks: number; frameworks: number };
  vulnerability_database: VulnerabilityDatabaseVersion;
  code_analysis_rules: { version: string | null; rules: number | null };
  exploit_intelligence?: ExploitIntelligenceFeed[];
  engines: EngineVersion[];
}

export interface ContentVersionsResource {
  type: "cloudsneeker-content-versions";
  id: string;
  attributes: ContentVersionsAttributes;
}
