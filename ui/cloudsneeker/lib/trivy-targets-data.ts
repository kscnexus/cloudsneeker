// Server-side loader for every scan target. The API pages at 100, and an
// organization that scans every repository has several hundred targets.

import { listTrivyTargets } from "@/cloudsneeker/actions/trivy";
import { responsePages } from "@/cloudsneeker/lib/app-security-scan-history";
import {
  isListResponse,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import type { TrivyTargetResource } from "@/cloudsneeker/types/trivy";

/** The API's largest page; 20 pages hold 2,000 targets. */
export const TARGET_PAGE_SIZE = 100;
export const MAX_TARGET_PAGES = 20;

export interface LoadedTargets {
  targets: TrivyTargetResource[];
  /** More pages exist than were read, or a later page failed. */
  truncated: boolean;
}

/**
 * Every target matching `filters`, read page by page: the first page tells
 * how many pages there are, then the rest load in parallel. Null when the
 * first page fails, so a failed request never reads as "no targets".
 */
export const loadAllTargets = async (
  filters: Record<string, string> = {},
  sort = "-inserted_at",
): Promise<LoadedTargets | null> => {
  const pageParams = (page: number) => ({
    ...filters,
    "page[size]": String(TARGET_PAGE_SIZE),
    "page[number]": String(page),
    sort,
  });

  const first: unknown = await listTrivyTargets(pageParams(1));
  if (!isListResponse(first)) return null;
  const targets = [...responseList<TrivyTargetResource>(first)];

  const pages = responsePages(first);
  const lastPage = Math.min(pages, MAX_TARGET_PAGES);
  const rest: unknown[] = await Promise.all(
    Array.from({ length: Math.max(0, lastPage - 1) }, (_, index) =>
      listTrivyTargets(pageParams(index + 2)),
    ),
  );
  let truncated = pages > MAX_TARGET_PAGES;
  for (const response of rest) {
    if (!isListResponse(response)) {
      truncated = true;
      continue;
    }
    targets.push(...responseList<TrivyTargetResource>(response));
  }
  return { targets, truncated };
};
