// Finding triage helpers (EB-010): merge triage rows into upstream findings
// responses so the inherited triage column and drawer show the stored status,
// and build the Triage page filters and links.

import { FINDINGS_PATH } from "@/cloudsneeker/lib/findings-links";
import { findingTriageHref } from "@/cloudsneeker/routes";
import type { FindingTriageLookupResource } from "@/cloudsneeker/types/finding-triage";
import {
  FINDING_TRIAGE_STATUS,
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageStatus,
} from "@/types/findings-triage";

/** Same cap as the API lookup endpoint. */
export const TRIAGE_LOOKUP_MAX_FINDINGS = 200;
export const TRIAGE_STATUS_PARAM = "status";
export const TRIAGE_PAGE_PARAM = "page";
export const TRIAGE_PAGE_SIZE = 25;

/** Status tabs on the Triage page, in workflow order. */
export const TRIAGE_STATUS_FILTERS = [
  FINDING_TRIAGE_STATUS.OPEN,
  FINDING_TRIAGE_STATUS.UNDER_REVIEW,
  FINDING_TRIAGE_STATUS.REMEDIATING,
  FINDING_TRIAGE_STATUS.REOPENED,
  FINDING_TRIAGE_STATUS.RESOLVED,
  FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
  FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
] as const satisfies readonly FindingTriageStatus[];

type FindingLikeResource = Record<string, unknown>;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const attributesOf = (
  resource: FindingLikeResource,
): Record<string, unknown> | undefined =>
  isRecord(resource.attributes) ? resource.attributes : undefined;

const resourcesOf = (response: unknown): FindingLikeResource[] => {
  if (!isRecord(response)) return [];
  const data = response.data;
  if (Array.isArray(data)) return data.filter(isRecord);
  return isRecord(data) ? [data] : [];
};

/** Finding row id: `attributes.finding_id` on group resources, else `id`. */
export const findingIdOf = (resource: FindingLikeResource): string | null => {
  const attributeId = attributesOf(resource)?.finding_id;
  if (typeof attributeId === "string" && attributeId) return attributeId;
  return typeof resource.id === "string" && resource.id ? resource.id : null;
};

const needsTriage = (resource: FindingLikeResource): boolean => {
  const attributes = attributesOf(resource);
  return attributes !== undefined && attributes.triage_status === undefined;
};

/**
 * Finding ids of rows that carry no triage fields yet (the open-source
 * findings API never sends them), deduplicated and capped.
 */
export const findingIdsNeedingTriage = (response: unknown): string[] => {
  const ids = new Set<string>();
  for (const resource of resourcesOf(response)) {
    if (!needsTriage(resource)) continue;
    const id = findingIdOf(resource);
    if (id) ids.add(id);
    if (ids.size >= TRIAGE_LOOKUP_MAX_FINDINGS) break;
  }
  return [...ids];
};

const lookupEntries = (
  lookup: unknown,
): Map<string, FindingTriageLookupResource["attributes"]> => {
  const entries = new Map<string, FindingTriageLookupResource["attributes"]>();
  if (!isRecord(lookup) || !Array.isArray(lookup.data)) return entries;
  for (const item of lookup.data) {
    if (!isRecord(item) || !isRecord(item.attributes)) continue;
    const attributes =
      item.attributes as unknown as FindingTriageLookupResource["attributes"];
    if (typeof attributes.finding_id === "string") {
      entries.set(attributes.finding_id, attributes);
    }
  }
  return entries;
};

const withTriageAttributes = (
  resource: FindingLikeResource,
  entries: Map<string, FindingTriageLookupResource["attributes"]>,
): FindingLikeResource => {
  if (!needsTriage(resource)) return resource;
  const id = findingIdOf(resource);
  const entry = id ? entries.get(id) : undefined;
  if (!entry) return resource;
  const attributes = attributesOf(resource);
  return {
    ...resource,
    attributes: {
      ...attributes,
      finding_uid: attributes?.finding_uid ?? entry.finding_uid,
      triage_id: entry.triage_id,
      triage_status: entry.triage_status,
      triage_notes_count: entry.triage_notes_count,
      triage_has_note: entry.triage_has_note,
    },
  };
};

/**
 * Copy triage fields from a `finding-triages/lookup` response onto the
 * matching rows of a findings response (list or single). Rows without a
 * triage keep their shape, so the inherited adapter falls back to open.
 */
export const mergeTriageLookup = <T>(response: T, lookup: unknown): T => {
  const entries = lookupEntries(lookup);
  if (entries.size === 0 || !isRecord(response)) return response;
  const data = response.data;
  if (Array.isArray(data)) {
    return {
      ...response,
      data: data.map((item) =>
        isRecord(item) ? withTriageAttributes(item, entries) : item,
      ),
    } as unknown as T;
  }
  if (isRecord(data)) {
    return {
      ...response,
      data: withTriageAttributes(data, entries),
    } as unknown as T;
  }
  return response;
};

export const parseTriageStatus = (
  value: string | string[] | undefined,
): FindingTriageStatus | null => {
  const candidate = Array.isArray(value) ? value[0] : value;
  return TRIAGE_STATUS_FILTERS.find((status) => status === candidate) ?? null;
};

export const parseTriagePage = (
  value: string | string[] | undefined,
): number => {
  const candidate = Number(Array.isArray(value) ? value[0] : value);
  return Number.isInteger(candidate) && candidate > 0 ? candidate : 1;
};

export const triageStatusLabel = (status: string): string =>
  FINDING_TRIAGE_STATUS_LABELS[status as FindingTriageStatus] ?? status;

/** Query for `GET /finding-triages` from the page filters. */
export const triageListSearchParams = ({
  status,
  page,
}: {
  status: FindingTriageStatus | null;
  page: number;
}): Record<string, string> => ({
  "page[number]": String(page),
  "page[size]": String(TRIAGE_PAGE_SIZE),
  sort: "-updated_at",
  ...(status ? { "filter[status]": status } : {}),
});

/** Triage page link for a status tab (null = all statuses). */
export const triagePageHref = (
  status: FindingTriageStatus | null,
  page = 1,
): string => {
  const params = new URLSearchParams();
  if (status) params.set(TRIAGE_STATUS_PARAM, status);
  if (page > 1) params.set(TRIAGE_PAGE_PARAM, String(page));
  const query = params.toString();
  return query ? `${findingTriageHref()}?${query}` : findingTriageHref();
};

/** Findings grouped under the triaged check, where the row and drawer live. */
export const triageFindingsHref = (checkId: string): string => {
  if (!checkId) return FINDINGS_PATH;
  const params = new URLSearchParams({ "filter[check_id__in]": checkId });
  return `${FINDINGS_PATH}?${params.toString()}`;
};
