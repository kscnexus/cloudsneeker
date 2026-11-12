// Which sources (providers) each report reads, so every report form offers
// only the sources that can contribute. Mirrors `SOURCE_PROVIDER_TYPES` in
// `api/src/backend/cloudsneeker_api/reports/catalog.py`; the API rejects any
// other source with a 400.

import {
  COMPLIANCE_PROVIDER_TYPES,
  COMPLIANCE_SAAS_PROVIDERS,
} from "@/cloudsneeker/compliance/single-scan-scope";
import {
  REPORT_TYPE_ID,
  type ReportTypeId,
} from "@/cloudsneeker/types/reports";

/** Kinds of sources a report can read. */
export const SOURCE_SCOPE = {
  ALL: "all",
  POSTURE: "posture",
  GOVERNANCE: "governance",
  APPSEC: "appsec",
  REPOSITORIES: "repositories",
  CONTAINERS: "containers",
} as const;

export type SourceScope = (typeof SOURCE_SCOPE)[keyof typeof SOURCE_SCOPE];

/** Groups the picker lists sources under. */
export const SOURCE_GROUP = {
  CLOUD: "cloud",
  SAAS: "saas",
  REPOSITORIES: "repositories",
  IMAGES: "images",
  CLUSTERS: "clusters",
} as const;

export type SourceGroup = (typeof SOURCE_GROUP)[keyof typeof SOURCE_GROUP];

const SOURCE_GROUP_LABEL: Record<SourceGroup, string> = {
  [SOURCE_GROUP.CLOUD]: "Cloud accounts",
  [SOURCE_GROUP.SAAS]: "SaaS accounts",
  [SOURCE_GROUP.REPOSITORIES]: "Repositories and code",
  [SOURCE_GROUP.IMAGES]: "Container images",
  [SOURCE_GROUP.CLUSTERS]: "Kubernetes clusters",
};

const REPOSITORY_TYPES = ["iac"] as const;
const IMAGE_TYPES = ["image"] as const;
const CLUSTER_TYPES = ["kubernetes"] as const;
/** Cloud Governance policies run on these provider types. */
export const GOVERNANCE_PROVIDER_TYPES = [
  "aws",
  "azure",
  "gcp",
  "kubernetes",
] as const;

const SCOPE_TYPES: Record<SourceScope, readonly string[] | null> = {
  [SOURCE_SCOPE.ALL]: null,
  [SOURCE_SCOPE.POSTURE]: COMPLIANCE_PROVIDER_TYPES,
  [SOURCE_SCOPE.GOVERNANCE]: GOVERNANCE_PROVIDER_TYPES,
  [SOURCE_SCOPE.APPSEC]: [
    ...REPOSITORY_TYPES,
    ...IMAGE_TYPES,
    ...CLUSTER_TYPES,
  ],
  [SOURCE_SCOPE.REPOSITORIES]: REPOSITORY_TYPES,
  [SOURCE_SCOPE.CONTAINERS]: [...IMAGE_TYPES, ...CLUSTER_TYPES],
};

const SCOPE_NOTE: Record<SourceScope, string | null> = {
  [SOURCE_SCOPE.ALL]: null,
  [SOURCE_SCOPE.POSTURE]: "Showing cloud and SaaS accounts only.",
  [SOURCE_SCOPE.GOVERNANCE]:
    "Showing cloud accounts that Cloud Governance policies run on (AWS, Azure, GCP, Kubernetes).",
  [SOURCE_SCOPE.APPSEC]:
    "Showing Application Security repositories, images, and clusters only.",
  [SOURCE_SCOPE.REPOSITORIES]:
    "Showing Application Security repositories and code only.",
  [SOURCE_SCOPE.CONTAINERS]:
    "Showing Application Security images and clusters only.",
};

/** Source scope of every report type (see the API catalog). */
export const REPORT_SOURCE_SCOPE: Record<ReportTypeId, SourceScope> = {
  [REPORT_TYPE_ID.EXECUTIVE]: SOURCE_SCOPE.ALL,
  [REPORT_TYPE_ID.EXCEPTIONS]: SOURCE_SCOPE.ALL,
  // Secrets are read from cloud scans as well as code, image, and clusters.
  [REPORT_TYPE_ID.SECRETS]: SOURCE_SCOPE.ALL,
  [REPORT_TYPE_ID.SECURITY_ASSESSMENT]: SOURCE_SCOPE.ALL,
  [REPORT_TYPE_ID.CLOUD_POSTURE]: SOURCE_SCOPE.POSTURE,
  [REPORT_TYPE_ID.COMPLIANCE]: SOURCE_SCOPE.POSTURE,
  [REPORT_TYPE_ID.CLOUD_ASSESSMENT]: SOURCE_SCOPE.POSTURE,
  [REPORT_TYPE_ID.GOVERNANCE_ASSESSMENT]: SOURCE_SCOPE.POSTURE,
  [REPORT_TYPE_ID.GOVERNANCE]: SOURCE_SCOPE.GOVERNANCE,
  [REPORT_TYPE_ID.SCA]: SOURCE_SCOPE.APPSEC,
  [REPORT_TYPE_ID.REMEDIATION]: SOURCE_SCOPE.APPSEC,
  [REPORT_TYPE_ID.LICENSES]: SOURCE_SCOPE.APPSEC,
  [REPORT_TYPE_ID.SBOM]: SOURCE_SCOPE.APPSEC,
  [REPORT_TYPE_ID.APPSEC_ASSESSMENT]: SOURCE_SCOPE.APPSEC,
  [REPORT_TYPE_ID.SAST]: SOURCE_SCOPE.REPOSITORIES,
  [REPORT_TYPE_ID.IAC]: SOURCE_SCOPE.REPOSITORIES,
  [REPORT_TYPE_ID.CONTAINER]: SOURCE_SCOPE.CONTAINERS,
};

/** A provider the picker can offer. */
export interface ReportSource {
  id: string;
  label: string;
  providerType: string;
}

export const sourceScopeOf = (reportType: string): SourceScope =>
  REPORT_SOURCE_SCOPE[reportType as ReportTypeId] ?? SOURCE_SCOPE.ALL;

/** Provider type a compliance framework id belongs to (`cis_2.0_aws`). */
export const frameworkProviderType = (
  complianceId: string | null | undefined,
): string | null => {
  const suffix = (complianceId ?? "").split("_").pop()?.toLowerCase() ?? "";
  return COMPLIANCE_PROVIDER_TYPES.includes(suffix) ? suffix : null;
};

/** Provider types a report reads, or `null` for every type. */
export const applicableProviderTypes = (
  reportType: string,
  complianceId?: string | null,
): readonly string[] | null => {
  if (reportType === REPORT_TYPE_ID.COMPLIANCE) {
    const frameworkType = frameworkProviderType(complianceId);
    if (frameworkType) return [frameworkType];
  }
  return SCOPE_TYPES[sourceScopeOf(reportType)];
};

export const isApplicableSource = (
  reportType: string,
  providerType: string,
  complianceId?: string | null,
): boolean => {
  const types = applicableProviderTypes(reportType, complianceId);
  return types === null || types.includes(providerType);
};

/** Sources the report reads, in the given order. */
export const sourcesForReport = <T extends { providerType: string }>(
  reportType: string,
  sources: T[],
  complianceId?: string | null,
): T[] =>
  sources.filter((source) =>
    isApplicableSource(reportType, source.providerType, complianceId),
  );

/** What the picker says about the list ("Showing cloud accounts only."). */
export const sourceScopeNote = (
  reportType: string,
  complianceId?: string | null,
): string | null => {
  if (reportType === REPORT_TYPE_ID.COMPLIANCE) {
    const frameworkType = frameworkProviderType(complianceId);
    if (frameworkType) {
      return "Showing only the accounts this framework covers.";
    }
  }
  return SCOPE_NOTE[sourceScopeOf(reportType)];
};

const SAAS = new Set<string>(COMPLIANCE_SAAS_PROVIDERS);

const groupOf = (scope: SourceScope, providerType: string): SourceGroup => {
  if (providerType === "iac") return SOURCE_GROUP.REPOSITORIES;
  if (providerType === "image") return SOURCE_GROUP.IMAGES;
  // A cluster is a cloud account in cloud reports and an Application
  // Security source in code and image reports.
  if (
    providerType === "kubernetes" &&
    (scope === SOURCE_SCOPE.APPSEC || scope === SOURCE_SCOPE.CONTAINERS)
  ) {
    return SOURCE_GROUP.CLUSTERS;
  }
  return SAAS.has(providerType) ? SOURCE_GROUP.SAAS : SOURCE_GROUP.CLOUD;
};

const GROUP_ORDER: SourceGroup[] = [
  SOURCE_GROUP.CLOUD,
  SOURCE_GROUP.SAAS,
  SOURCE_GROUP.REPOSITORIES,
  SOURCE_GROUP.IMAGES,
  SOURCE_GROUP.CLUSTERS,
];

export interface SourceGroupList<T> {
  group: SourceGroup;
  label: string;
  sources: T[];
}

/** Applicable sources grouped (cloud, SaaS, repositories, images, clusters). */
export const groupReportSources = <T extends ReportSource>(
  reportType: string,
  sources: T[],
  complianceId?: string | null,
): SourceGroupList<T>[] => {
  const scope = sourceScopeOf(reportType);
  const byGroup = new Map<SourceGroup, T[]>();
  for (const source of sourcesForReport(reportType, sources, complianceId)) {
    const group = groupOf(scope, source.providerType);
    byGroup.set(group, [...(byGroup.get(group) ?? []), source]);
  }
  return GROUP_ORDER.filter((group) => byGroup.has(group)).map((group) => ({
    group,
    label: SOURCE_GROUP_LABEL[group],
    sources: [...(byGroup.get(group) ?? [])].sort((a, b) =>
      a.label.localeCompare(b.label),
    ),
  }));
};

/** Case-insensitive match on the label and the provider type. */
export const matchesSourceQuery = (
  source: ReportSource,
  query: string,
): boolean => {
  const needle = query.trim().toLowerCase();
  if (!needle) return true;
  return (
    source.label.toLowerCase().includes(needle) ||
    source.providerType.toLowerCase().includes(needle)
  );
};

/**
 * Selected ids the report reads. Ids of unknown providers are kept (the API
 * decides on them); ids of a known provider of another type are dropped.
 */
export const applicableProviderIds = (
  reportType: string,
  providerIds: string[],
  providerTypes: Readonly<Record<string, string>>,
  complianceId?: string | null,
): string[] =>
  providerIds.filter((id) => {
    const type = providerTypes[id];
    return (
      type === undefined || isApplicableSource(reportType, type, complianceId)
    );
  });

/** Provider id to provider type, for `applicableProviderIds`. */
export const providerTypeMap = (
  sources: { id: string; providerType?: string }[],
): Record<string, string> =>
  Object.fromEntries(
    sources
      .filter((source) => source.providerType)
      .map((source) => [source.id, source.providerType as string]),
  );

/** Lists longer than this get a search box. */
export const SOURCE_SEARCH_THRESHOLD = 10;
