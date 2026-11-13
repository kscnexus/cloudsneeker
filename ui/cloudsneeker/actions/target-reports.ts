"use server";

import { createReportRun, getReportRun } from "@/cloudsneeker/actions/reports";
import { listTrivyTargets } from "@/cloudsneeker/actions/trivy";
import {
  repositoryReportJobs,
  type TargetReportJob,
  type TargetReportType,
} from "@/cloudsneeker/lib/target-reports";
import {
  REPORT_FORMAT,
  REPORT_RUN_STATUS,
  type ReportRunResource,
  type ReportRunStatus,
} from "@/cloudsneeker/types/reports";
import {
  TRIVY_MODE,
  type TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";

const PAGE_SIZE = 100;
/** Stops paging a runaway listing; far above any tenant's target count. */
const MAX_PAGES = 50;
const MAX_STATUS_IDS = 50;

type ActionError = { error: string };

const errorText = (result: unknown, fallback: string): string | null => {
  if (result && typeof result === "object" && "error" in result) {
    const { error } = result as { error?: unknown };
    if (!error) return null;
    return typeof error === "string" ? error : fallback;
  }
  return null;
};

/** Start a PDF SCA or SAST report limited to one target. */
export const startTargetReport = async (
  targetId: string,
  reportType: TargetReportType,
): Promise<{ runId: string } | ActionError> => {
  const result = await createReportRun({
    reportType,
    params: { target_id: targetId },
    formats: [REPORT_FORMAT.PDF],
  });
  const error = errorText(result, "The report could not be started.");
  if (error) return { error };
  const runId = (result as { data?: ReportRunResource })?.data?.id;
  return runId ? { runId } : { error: "The report could not be started." };
};

/** Current status of each run; unreadable runs count as failed. */
export const getTargetReportStatuses = async (
  runIds: string[],
): Promise<Record<string, ReportRunStatus>> => {
  const ids = runIds.slice(0, MAX_STATUS_IDS);
  const entries = await Promise.all(
    ids.map(async (runId) => {
      const result = await getReportRun(runId);
      const status = (result as { data?: ReportRunResource })?.data?.attributes
        ?.status;
      return [runId, status ?? REPORT_RUN_STATUS.FAILED] as const;
    }),
  );
  return Object.fromEntries(entries);
};

const loadTargetsByMode = async (
  mode: string,
): Promise<TrivyTargetResource[] | null> => {
  const targets: TrivyTargetResource[] = [];
  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const result = await listTrivyTargets({
      "filter[mode]": mode,
      "page[size]": String(PAGE_SIZE),
      "page[number]": String(page),
      sort: "name",
    });
    if (errorText(result, "error") || !Array.isArray(result?.data)) {
      return null;
    }
    targets.push(...(result.data as TrivyTargetResource[]));
    const pages = Number(result?.meta?.pagination?.pages ?? page);
    if (page >= pages || result.data.length < PAGE_SIZE) break;
  }
  return targets;
};

/** SCA jobs for every repository target and SAST jobs for every SAST target. */
export const listRepositoryReportJobs = async (): Promise<
  { jobs: TargetReportJob[] } | ActionError
> => {
  const [repos, sast] = await Promise.all([
    loadTargetsByMode(TRIVY_MODE.REPO),
    loadTargetsByMode(TRIVY_MODE.SAST),
  ]);
  if (!repos || !sast) {
    return { error: "Targets could not be loaded. Try again in a moment." };
  }
  return { jobs: repositoryReportJobs([...repos, ...sast]) };
};
