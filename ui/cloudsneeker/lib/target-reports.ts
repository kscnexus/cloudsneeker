// Per-target SCA and SAST reports: which report a target gets, and the job
// list the "download every repository's reports" action works through. The
// API names each file after its target (`<target>-sca-<date>.pdf`).

import {
  REPORT_RUN_STATUS,
  REPORT_TYPE_ID,
  type ReportRunStatus,
} from "@/cloudsneeker/types/reports";
import {
  TRIVY_MODE,
  type TrivyMode,
  type TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";

export const TARGET_REPORT_TYPE = {
  SCA: REPORT_TYPE_ID.SCA,
  SAST: REPORT_TYPE_ID.SAST,
} as const;

export type TargetReportType =
  (typeof TARGET_REPORT_TYPE)[keyof typeof TARGET_REPORT_TYPE];

export const TARGET_REPORT_LABEL: Record<TargetReportType, string> = {
  sca: "SCA report",
  sast: "SAST report",
};

/** Target modes the SCA report reads (matches the API `TARGET_MODES`). */
const SCA_MODES = new Set<string>([
  TRIVY_MODE.REPO,
  TRIVY_MODE.FS,
  TRIVY_MODE.SBOM,
  TRIVY_MODE.IMAGE,
  TRIVY_MODE.K8S,
]);

/** Repository targets: dependency scans and static analysis of source code. */
const REPOSITORY_MODES = new Set<string>([TRIVY_MODE.REPO, TRIVY_MODE.SAST]);

export const reportTypeForTargetMode = (
  mode: TrivyMode | string,
): TargetReportType | null => {
  if (mode === TRIVY_MODE.SAST) return TARGET_REPORT_TYPE.SAST;
  if (SCA_MODES.has(mode)) return TARGET_REPORT_TYPE.SCA;
  return null;
};

export interface TargetReportJob {
  targetId: string;
  targetName: string;
  reportType: TargetReportType;
}

/** One SCA job per repository target and one SAST job per SAST target. */
export const repositoryReportJobs = (
  targets: TrivyTargetResource[],
): TargetReportJob[] =>
  targets
    .filter((target) => REPOSITORY_MODES.has(target.attributes.mode))
    .map((target) => ({
      targetId: target.id,
      targetName: target.attributes.name,
      reportType: reportTypeForTargetMode(
        target.attributes.mode,
      ) as TargetReportType,
    }))
    .sort(
      (a, b) =>
        a.targetName.localeCompare(b.targetName) ||
        a.reportType.localeCompare(b.reportType),
    );

export const isFinishedReportStatus = (status: ReportRunStatus): boolean =>
  status === REPORT_RUN_STATUS.COMPLETED || status === REPORT_RUN_STATUS.FAILED;

export interface TargetReportProgress {
  total: number;
  ready: number;
  failed: number;
}

export const describeReportProgress = ({
  total,
  ready,
  failed,
}: TargetReportProgress): string => {
  const done = ready + failed;
  const base =
    done < total
      ? `Preparing reports: ${done} of ${total}`
      : `${ready} of ${total} reports downloaded`;
  return failed > 0 ? `${base} (${failed} failed)` : base;
};

/** Run `worker` over `items` with at most `limit` calls in flight. */
export const runWithConcurrency = async <T>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<void>,
  shouldStop: () => boolean = () => false,
): Promise<void> => {
  let next = 0;
  const lanes = Array.from(
    { length: Math.max(1, Math.min(limit, items.length)) },
    async () => {
      while (next < items.length && !shouldStop()) {
        const index = next;
        next += 1;
        await worker(items[index], index);
      }
    },
  );
  await Promise.all(lanes);
};
