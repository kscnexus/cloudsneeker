import { APPSEC_SEGMENT } from "@/cloudsneeker/lib/appsec";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type { TrivyRunResource } from "@/cloudsneeker/types/trivy";

/** Current scans shown per target on the Scans tab. */
export const SCANS_PER_TARGET = 20;
/** Scans older than this are archived by the API's daily task. */
export const SCAN_ARCHIVE_DAYS = 365;
/** Archived scans per page in the archive view. */
export const ARCHIVED_SCANS_PAGE_SIZE = 50;

export const SCAN_HISTORY_VIEW = {
  CURRENT: "current",
  ARCHIVED: "archived",
} as const;

export type ScanHistoryView =
  (typeof SCAN_HISTORY_VIEW)[keyof typeof SCAN_HISTORY_VIEW];

export const SCAN_HISTORY_PARAM = "history";
export const SCAN_HISTORY_PAGE_PARAM = "page";

type QueryValue = string | string[] | undefined;

const first = (value: QueryValue) => (Array.isArray(value) ? value[0] : value);

export const getScanHistoryView = (value: QueryValue): ScanHistoryView =>
  first(value) === SCAN_HISTORY_VIEW.ARCHIVED
    ? SCAN_HISTORY_VIEW.ARCHIVED
    : SCAN_HISTORY_VIEW.CURRENT;

export const getScanHistoryPage = (value: QueryValue): number => {
  const page = Number.parseInt(first(value) ?? "", 10);
  return Number.isFinite(page) && page >= 1 ? page : 1;
};

/** Scans page, current or archived, with an optional archive page. */
export const scanHistoryHref = (view: ScanHistoryView, page = 1): string => {
  const base = appSecurityHref(APPSEC_SEGMENT.SCANS);
  if (view === SCAN_HISTORY_VIEW.CURRENT) return base;
  const params = new URLSearchParams({ [SCAN_HISTORY_PARAM]: view });
  if (page > 1) params.set(SCAN_HISTORY_PAGE_PARAM, String(page));
  return `${base}?${params.toString()}`;
};

/** `meta.pagination.pages` of a list response; 1 when the API sent none. */
export const responsePages = (response: unknown): number => {
  const pages = (
    response as { meta?: { pagination?: { pages?: unknown } } } | null
  )?.meta?.pagination?.pages;
  return typeof pages === "number" && pages >= 1 ? Math.floor(pages) : 1;
};

export interface RunGroup {
  targetId: string;
  targetName: string;
  targetMode: string;
  runs: TrivyRunResource[];
}

const runTime = (run: TrivyRunResource): number => {
  const time = Date.parse(run.attributes.inserted_at ?? "");
  return Number.isNaN(time) ? 0 : time;
};

/** Runs grouped per target; newest run first in each, newest group first. */
export const groupRunsByTarget = (runs: TrivyRunResource[]): RunGroup[] => {
  const groups = new Map<string, RunGroup>();
  const sorted = [...runs].sort((a, b) => runTime(b) - runTime(a));
  for (const run of sorted) {
    const { target_id, target_name, target_mode } = run.attributes;
    const group = groups.get(target_id);
    if (group) {
      group.runs.push(run);
      continue;
    }
    groups.set(target_id, {
      targetId: target_id,
      targetName: target_name || target_id,
      targetMode: target_mode || run.attributes.summary?.mode || "",
      runs: [run],
    });
  }
  return Array.from(groups.values());
};
