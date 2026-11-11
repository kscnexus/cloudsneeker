// Global search (`GET /search`): one query across Cloud Security,
// Application Security and Governance. The API returns groups with a count
// and the first hits; this module labels them and builds their links.

import { BRAND } from "@/cloudsneeker/brand";
import {
  areaFindingHref,
  areaFindingsPageHref,
} from "@/cloudsneeker/lib/area-findings";
import {
  FINDING_AREA,
  type FindingArea,
} from "@/cloudsneeker/types/area-findings";

export const SEARCH_PATH = "/search";
export const SEARCH_PARAM = "q";
export const SEARCH_MIN_LENGTH = 2;
export const SEARCH_MAX_LENGTH = 200;

export const SEARCH_GROUP = {
  CLOUD_FINDINGS: "cloud_findings",
  APPLICATION_FINDINGS: "application_security_findings",
  GOVERNANCE_FINDINGS: "governance_findings",
  ACCOUNTS: "cloud_accounts",
  TARGETS: "application_targets",
  APPLICATIONS: "applications",
  POLICIES: "governance_policies",
  ALERT_RULES: "alert_rules",
} as const;

export type SearchGroupKind = (typeof SEARCH_GROUP)[keyof typeof SEARCH_GROUP];

const GROUP_VALUES = new Set<string>(Object.values(SEARCH_GROUP));

const isSearchGroupKind = (value: unknown): value is SearchGroupKind =>
  typeof value === "string" && GROUP_VALUES.has(value);

const FINDING_GROUP_AREA: Partial<Record<SearchGroupKind, FindingArea>> = {
  [SEARCH_GROUP.CLOUD_FINDINGS]: FINDING_AREA.CLOUD,
  [SEARCH_GROUP.APPLICATION_FINDINGS]: FINDING_AREA.APPLICATION_SECURITY,
  [SEARCH_GROUP.GOVERNANCE_FINDINGS]: FINDING_AREA.GOVERNANCE,
};

export const SEARCH_GROUP_LABEL: Record<SearchGroupKind, string> = {
  [SEARCH_GROUP.CLOUD_FINDINGS]: `${BRAND.cloudSecurityName} findings`,
  [SEARCH_GROUP.APPLICATION_FINDINGS]: `${BRAND.appSecurityName} findings`,
  [SEARCH_GROUP.GOVERNANCE_FINDINGS]: `${BRAND.governanceName} findings`,
  [SEARCH_GROUP.ACCOUNTS]: "Cloud accounts",
  [SEARCH_GROUP.TARGETS]: `${BRAND.appSecurityName} targets`,
  [SEARCH_GROUP.APPLICATIONS]: "Applications",
  [SEARCH_GROUP.POLICIES]: `${BRAND.governanceName} policies`,
  [SEARCH_GROUP.ALERT_RULES]: "Alert rules",
};

export interface SearchHitItem {
  id: string;
  title: string;
  subtitle: string;
  href: string;
  severity: string;
}

export interface SearchGroupItem {
  kind: SearchGroupKind;
  label: string;
  count: number;
  hits: SearchHitItem[];
  /** The group's own list, filtered by the same text. */
  moreHref: string;
}

/** The query from `?q=`, trimmed; empty when too short to search. */
export const searchQueryOf = (
  params: Record<string, string | string[] | undefined>,
): string => {
  const raw = params[SEARCH_PARAM];
  const value = (Array.isArray(raw) ? raw[0] : raw) ?? "";
  const text = value.split(/\s+/).filter(Boolean).join(" ");
  return text.length >= SEARCH_MIN_LENGTH
    ? text.slice(0, SEARCH_MAX_LENGTH)
    : "";
};

const withQuery = (path: string, params: Record<string, string>): string =>
  `${path}?${new URLSearchParams(params).toString()}`;

/** Link to the full list of a group, filtered by the query. */
export const searchMoreHref = (kind: SearchGroupKind, text: string): string => {
  const area = FINDING_GROUP_AREA[kind];
  if (area) return areaFindingsPageHref(area, { search: text });
  switch (kind) {
    case SEARCH_GROUP.ACCOUNTS:
      return withQuery("/providers", { "filter[search]": text });
    case SEARCH_GROUP.TARGETS:
      return withQuery("/application-security/scans", { q: text });
    case SEARCH_GROUP.APPLICATIONS:
      return "/application-security/applications";
    case SEARCH_GROUP.POLICIES:
      return withQuery("/governance", { tab: "policies", q: text });
    default:
      return withQuery("/alerts", { "filter[search]": text });
  }
};

const text = (value: unknown): string =>
  typeof value === "string" ? value : "";

/** Link to one hit. */
export const searchHitHref = (
  kind: SearchGroupKind,
  hit: Record<string, unknown>,
): string => {
  const id = text(hit.id);
  const area = FINDING_GROUP_AREA[kind];
  if (area)
    return areaFindingHref(area, { uid: id, checkId: text(hit.check_id) });
  switch (kind) {
    case SEARCH_GROUP.ACCOUNTS:
      return withQuery("/providers", {
        "filter[search]": text(hit.uid) || text(hit.title),
      });
    case SEARCH_GROUP.TARGETS:
      return `/application-security/${encodeURIComponent(id)}`;
    case SEARCH_GROUP.APPLICATIONS:
      return `/application-security/applications/${encodeURIComponent(id)}`;
    case SEARCH_GROUP.POLICIES:
      return `/governance/${encodeURIComponent(id)}`;
    default:
      return withQuery("/alerts", { edit: id });
  }
};

/** API groups as display items; unknown groups and malformed hits dropped. */
export const toSearchGroups = (
  response: unknown,
  query: string,
): SearchGroupItem[] => {
  const rows = (response as { data?: unknown } | undefined)?.data;
  if (!Array.isArray(rows)) return [];
  return rows.flatMap((row) => {
    const { id, attributes } = (row ?? {}) as {
      id?: unknown;
      attributes?: { count?: unknown; hits?: unknown };
    };
    if (!isSearchGroupKind(id)) return [];
    const hits = Array.isArray(attributes?.hits) ? attributes.hits : [];
    return [
      {
        kind: id,
        label: SEARCH_GROUP_LABEL[id],
        count: typeof attributes?.count === "number" ? attributes.count : 0,
        moreHref: searchMoreHref(id, query),
        hits: hits.flatMap((hit) => {
          const record = (hit ?? {}) as Record<string, unknown>;
          if (!text(record.id)) return [];
          return [
            {
              id: text(record.id),
              title: text(record.title) || text(record.id),
              subtitle: text(record.subtitle),
              severity: text(record.severity),
              href: searchHitHref(id, record),
            },
          ];
        }),
      },
    ];
  });
};

/** Total hits across groups. */
export const searchTotal = (groups: SearchGroupItem[]): number =>
  groups.reduce((sum, group) => sum + group.count, 0);
