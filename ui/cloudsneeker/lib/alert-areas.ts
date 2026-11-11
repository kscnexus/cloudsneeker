// Product areas (modules) of an alert rule. The API reads the `area` leaf
// field of the condition (`cloudsneeker_api/services/alert_evaluation.py`):
// without one, a rule covers Cloud Security and Application Security.

import { BRAND } from "@/cloudsneeker/brand";
import {
  FINDING_AREA,
  type FindingArea,
} from "@/cloudsneeker/types/area-findings";

export const ALERT_AREA_FILTER_KEY = "filter[area__in]";

/** Query parameters the Alerts page reads to open a new rule. */
export const NEW_ALERT_PARAM = "new";
export const NEW_ALERT_AREA_PARAM = "area";

export const ALERT_AREA_OPTIONS: readonly {
  value: FindingArea;
  label: string;
}[] = [
  { value: FINDING_AREA.CLOUD, label: BRAND.cloudSecurityName },
  { value: FINDING_AREA.APPLICATION_SECURITY, label: BRAND.appSecurityName },
  { value: FINDING_AREA.GOVERNANCE, label: BRAND.governanceName },
];

export const DEFAULT_ALERT_AREAS: readonly FindingArea[] = [
  FINDING_AREA.CLOUD,
  FINDING_AREA.APPLICATION_SECURITY,
];

const AREA_VALUES = new Set<string>(Object.values(FINDING_AREA));

export const isFindingArea = (value: unknown): value is FindingArea =>
  typeof value === "string" && AREA_VALUES.has(value);

export const alertAreaLabel = (area: FindingArea): string =>
  ALERT_AREA_OPTIONS.find((option) => option.value === area)?.label ?? area;

interface ConditionNode {
  filter?: Record<string, unknown>;
  children?: ConditionNode[];
  child?: ConditionNode;
}

/** Areas a stored condition covers (defaults when none is named). */
export const alertConditionAreas = (condition: unknown): FindingArea[] => {
  const found = new Set<FindingArea>();
  const visit = (node: unknown) => {
    if (!node || typeof node !== "object") return;
    const current = node as ConditionNode;
    const raw = current.filter?.area;
    const values = Array.isArray(raw) ? raw : raw ? [raw] : [];
    values.filter(isFindingArea).forEach((area) => found.add(area));
    current.children?.forEach(visit);
    if (current.child) visit(current.child);
  };
  visit(condition);
  const named = ALERT_AREA_OPTIONS.map((option) => option.value).filter(
    (area) => found.has(area),
  );
  return named.length > 0 ? named : [...DEFAULT_ALERT_AREAS];
};

/** Link that opens the Alerts page with a new rule for one area. */
export const newAlertHref = (area: FindingArea): string => {
  const params = new URLSearchParams({
    [NEW_ALERT_PARAM]: "1",
    [NEW_ALERT_AREA_PARAM]: area,
  });
  return `/alerts?${params.toString()}`;
};

/** Area requested by `/alerts?new=1&area=...`, or null. */
export const requestedNewAlertArea = (
  params: Record<string, string | string[] | undefined>,
): FindingArea | null => {
  const flag = params[NEW_ALERT_PARAM];
  if (!flag) return null;
  const raw = params[NEW_ALERT_AREA_PARAM];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return isFindingArea(value) ? value : FINDING_AREA.CLOUD;
};
