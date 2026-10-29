// Pure helpers for the Application Security hub dashboard: KPI totals,
// product categories (Dependencies, Code, Containers, ...) and the target
// filter those categories drive.

import { appSecurityHref } from "@/cloudsneeker/routes";
import {
  TRIVY_MODE,
  TRIVY_RUN_STATUS,
  type TrivyMode,
  type TrivyRunResource,
  type TrivyRunStatus,
  type TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";

export const APP_SECURITY_CATEGORY = {
  DEPENDENCIES: "dependencies",
  CODE: "code",
  CONTAINERS: "containers",
  IAC: "iac",
  SECRETS: "secrets",
  SBOM: "sbom",
  KUBERNETES: "kubernetes",
} as const;

export type AppSecurityCategory =
  (typeof APP_SECURITY_CATEGORY)[keyof typeof APP_SECURITY_CATEGORY];

/** Query parameter that filters the target list by category. */
export const APP_SECURITY_CATEGORY_PARAM = "category";

/** Scanner name a target needs to count under Secrets. */
const SECRET_SCANNER = "secret";

/** Scanners a target runs when its config does not list any (API default). */
const DEFAULT_SCANNERS = ["vuln", "misconfig", SECRET_SCANNER] as const;

export interface AppSecurityCategoryDefinition {
  id: AppSecurityCategory;
  label: string;
  description: string;
  modes: readonly TrivyMode[];
  /** Only targets that run this scanner belong to the category. */
  scanner?: string;
}

export const APP_SECURITY_CATEGORIES: readonly AppSecurityCategoryDefinition[] =
  [
    {
      id: APP_SECURITY_CATEGORY.DEPENDENCIES,
      label: "Dependencies",
      description: "Vulnerable open-source packages in repositories and code archives.",
      modes: [TRIVY_MODE.REPO, TRIVY_MODE.FS],
    },
    {
      id: APP_SECURITY_CATEGORY.CODE,
      label: "Code (SAST)",
      description: "Security bugs in your own source code.",
      modes: [TRIVY_MODE.SAST],
    },
    {
      id: APP_SECURITY_CATEGORY.CONTAINERS,
      label: "Containers",
      description: "Vulnerable packages and misconfigurations in images.",
      modes: [TRIVY_MODE.IMAGE],
    },
    {
      id: APP_SECURITY_CATEGORY.IAC,
      label: "Infrastructure as Code",
      description: "Misconfigured Terraform, CloudFormation and manifests.",
      modes: [TRIVY_MODE.IAC],
    },
    {
      id: APP_SECURITY_CATEGORY.SECRETS,
      label: "Secrets",
      description: "Keys, tokens and passwords committed to code or images.",
      modes: [TRIVY_MODE.REPO, TRIVY_MODE.FS, TRIVY_MODE.IAC, TRIVY_MODE.IMAGE],
      scanner: SECRET_SCANNER,
    },
    {
      id: APP_SECURITY_CATEGORY.SBOM,
      label: "SBOM",
      description: "Known vulnerabilities in the components an SBOM lists.",
      modes: [TRIVY_MODE.SBOM],
    },
    {
      id: APP_SECURITY_CATEGORY.KUBERNETES,
      label: "Kubernetes",
      description: "Workload and cluster misconfigurations.",
      modes: [TRIVY_MODE.K8S],
    },
  ];

const CATEGORY_IDS = new Set<string>(Object.values(APP_SECURITY_CATEGORY));

/** Category from the `?category=` query value, or `null` for none/unknown. */
export const getAppSecurityCategory = (
  value: string | string[] | undefined,
): AppSecurityCategory | null => {
  const raw = Array.isArray(value) ? value[0] : value;
  return raw && CATEGORY_IDS.has(raw) ? (raw as AppSecurityCategory) : null;
};

export const categoryDefinition = (
  category: AppSecurityCategory,
): AppSecurityCategoryDefinition | undefined =>
  APP_SECURITY_CATEGORIES.find((item) => item.id === category);

export const appSecurityCategoryHref = (
  category: AppSecurityCategory | null,
): string => {
  const base = appSecurityHref();
  return category
    ? `${base}?${APP_SECURITY_CATEGORY_PARAM}=${encodeURIComponent(category)}`
    : base;
};

export const targetScanners = (target: TrivyTargetResource): string[] => {
  const scanners = target.attributes.config?.scanners;
  return Array.isArray(scanners) && scanners.length > 0
    ? scanners
    : [...DEFAULT_SCANNERS];
};

export const targetMatchesCategory = (
  target: TrivyTargetResource,
  category: AppSecurityCategory,
): boolean => {
  const definition = categoryDefinition(category);
  if (!definition) return false;
  if (!definition.modes.includes(target.attributes.mode)) return false;
  return definition.scanner
    ? targetScanners(target).includes(definition.scanner)
    : true;
};

export const filterTargetsByCategory = (
  targets: TrivyTargetResource[],
  category: AppSecurityCategory | null,
): TrivyTargetResource[] =>
  category
    ? targets.filter((target) => targetMatchesCategory(target, category))
    : targets;

const runScanId = (run: TrivyRunResource): string =>
  run.attributes.scan_id || run.attributes.summary?.scan_id || "";

/**
 * Latest completed run per target. `runs` must be newest first, which is how
 * the hub requests them (`sort=-inserted_at`).
 */
export const latestCompletedRunByTarget = (
  runs: TrivyRunResource[],
): Map<string, TrivyRunResource> => {
  const latest = new Map<string, TrivyRunResource>();
  for (const run of runs) {
    if (run.attributes.status !== TRIVY_RUN_STATUS.COMPLETED) continue;
    if (!latest.has(run.attributes.target_id)) {
      latest.set(run.attributes.target_id, run);
    }
  }
  return latest;
};

const ACTIVE_RUN_STATUSES = new Set<TrivyRunStatus>([
  TRIVY_RUN_STATUS.PENDING,
  TRIVY_RUN_STATUS.RUNNING,
]);

export interface AppSecurityLastRun {
  runId: string;
  targetId: string;
  targetName: string;
  status: TrivyRunStatus;
  insertedAt: string | null;
  href: string;
}

export interface AppSecurityCategorySummary {
  id: AppSecurityCategory;
  label: string;
  description: string;
  targetCount: number;
  /** Findings from each matching target's latest completed scan. */
  findingCount: number | null;
  href: string;
}

export interface AppSecurityDashboard {
  targetCount: number;
  scheduledTargetCount: number;
  runCount: number;
  activeRunCount: number;
  failedRunCount: number;
  lastRun: AppSecurityLastRun | null;
  /** Scan of each target's latest completed run; feeds severity totals. */
  latestScanIds: string[];
  latestFindingCount: number | null;
  categories: AppSecurityCategorySummary[];
}

interface AppSecurityDashboardInput {
  targets: TrivyTargetResource[];
  /** Newest first. */
  runs: TrivyRunResource[];
  /** Total runs reported by the API; defaults to `runs.length`. */
  runTotal?: number | null;
}

const sumFindings = (runs: TrivyRunResource[]): number | null => {
  let total: number | null = null;
  for (const run of runs) {
    const count = run.attributes.summary?.finding_count;
    if (typeof count === "number") total = (total ?? 0) + count;
  }
  return total;
};

export const buildAppSecurityDashboard = ({
  targets,
  runs,
  runTotal,
}: AppSecurityDashboardInput): AppSecurityDashboard => {
  const targetIds = new Set(targets.map((target) => target.id));
  const latestByTarget = latestCompletedRunByTarget(runs);
  const latestRuns = Array.from(latestByTarget.entries())
    .filter(([targetId]) => targetIds.has(targetId))
    .map(([, run]) => run);

  const first = runs[0];
  const lastRun: AppSecurityLastRun | null = first
    ? {
        runId: first.id,
        targetId: first.attributes.target_id,
        targetName: first.attributes.target_name || first.attributes.target_id,
        status: first.attributes.status,
        insertedAt: first.attributes.inserted_at ?? null,
        href: appSecurityHref(first.attributes.target_id, "runs", first.id),
      }
    : null;

  const categories = APP_SECURITY_CATEGORIES.map((definition) => {
    const matching = targets.filter((target) =>
      targetMatchesCategory(target, definition.id),
    );
    const matchingRuns = matching
      .map((target) => latestByTarget.get(target.id))
      .filter((run): run is TrivyRunResource => Boolean(run));
    return {
      id: definition.id,
      label: definition.label,
      description: definition.description,
      targetCount: matching.length,
      findingCount: sumFindings(matchingRuns),
      href: appSecurityCategoryHref(definition.id),
    };
  });

  return {
    targetCount: targets.length,
    scheduledTargetCount: targets.filter(
      (target) => target.attributes.schedule_enabled,
    ).length,
    runCount: runTotal ?? runs.length,
    activeRunCount: runs.filter((run) =>
      ACTIVE_RUN_STATUSES.has(run.attributes.status),
    ).length,
    failedRunCount: runs.filter(
      (run) => run.attributes.status === TRIVY_RUN_STATUS.FAILED,
    ).length,
    lastRun,
    latestScanIds: Array.from(
      new Set(latestRuns.map(runScanId).filter(Boolean)),
    ),
    latestFindingCount: sumFindings(latestRuns),
    categories,
  };
};
