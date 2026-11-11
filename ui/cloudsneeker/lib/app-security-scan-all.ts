import {
  SAST_RULESET,
  TRIVY_MODE,
  type TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";

/** Repositories handled per server action call, so each call stays short. */
export const SCAN_ALL_BATCH_SIZE = 10;

/** Target names are 3-100 characters and unique per tenant. */
const NAME_MIN_LENGTH = 3;
const NAME_MAX_LENGTH = 100;

/** An IaC provider: one connected Git repository. */
export interface RepositorySource {
  id: string;
  uid: string;
  alias?: string | null;
}

/** Target types "Scan all repositories" runs on every repository. */
export const SCAN_ALL_MODES = [TRIVY_MODE.REPO, TRIVY_MODE.SAST] as const;

export type ScanAllMode = (typeof SCAN_ALL_MODES)[number];

/** Profile of new code repository targets: every scanner the type supports. */
export const SCAN_ALL_REPO_PROFILE = "builtin:full";

/** Name suffix of the static analysis target created for a repository. */
const SAST_NAME_SUFFIX = " (SAST)";

/** One scan to start; without `targetId` the target is created first. */
export interface RepositoryScanItem {
  providerId: string;
  repositoryUrl: string;
  name: string;
  mode: ScanAllMode;
  targetId?: string;
}

export interface RepositoryScanResult {
  providerId: string;
  name: string;
  mode: ScanAllMode;
  started: boolean;
  message?: string;
}

/** Config of a target created by "Scan all repositories". */
export const scanAllTargetConfig = (
  item: RepositoryScanItem,
): Record<string, unknown> =>
  item.mode === TRIVY_MODE.SAST
    ? {
        repository_url: item.repositoryUrl,
        rulesets: [SAST_RULESET.AUTO],
        exclude: [],
      }
    : { repository_url: item.repositoryUrl, profile: SCAN_ALL_REPO_PROFILE };

/** `owner/repo` from an SSH or HTTPS clone URL; the input when it is neither. */
export const repositoryNameFromUrl = (url: string): string => {
  const trimmed = url.trim();
  const scp = trimmed.match(/^[\w.-]+@[\w.-]+:(?!\/\/)(.+)$/);
  let path: string | null = scp ? scp[1] : null;
  if (!path) {
    try {
      path = new URL(trimmed).pathname;
    } catch {
      return trimmed;
    }
  }
  return path
    .replace(/^\/+|\/+$/g, "")
    .replace(/\.git$/, "")
    .trim();
};

const fitName = (base: string): string => {
  const name = base.trim();
  const padded =
    name.length >= NAME_MIN_LENGTH ? name : `Repository ${name}`.trim();
  return padded.slice(0, NAME_MAX_LENGTH);
};

const uniqueName = (base: string, used: Set<string>): string => {
  let name = fitName(base);
  for (let suffix = 2; used.has(name); suffix += 1) {
    const tail = ` (${suffix})`;
    name = `${fitName(base).slice(0, NAME_MAX_LENGTH - tail.length)}${tail}`;
  }
  used.add(name);
  return name;
};

/**
 * What "Scan all repositories" does for each connected repository: one code
 * repository scan (dependencies, misconfigurations, secrets, licenses) and
 * one static analysis scan (code weaknesses). An existing target of each
 * type is rescanned; a missing one is created, named after the repository.
 */
export const planRepositoryScans = (
  repositories: RepositorySource[],
  targets: TrivyTargetResource[],
): RepositoryScanItem[] => {
  const usedNames = new Set(targets.map((target) => target.attributes.name));
  const existing = new Map<string, TrivyTargetResource>();
  for (const target of targets) {
    const key = `${target.attributes.mode}:${target.attributes.provider_id}`;
    if (!existing.has(key)) existing.set(key, target);
  }

  return repositories.flatMap((repository) => {
    const base =
      repository.alias?.trim() || repositoryNameFromUrl(repository.uid);
    return SCAN_ALL_MODES.map((mode): RepositoryScanItem => {
      const target = existing.get(`${mode}:${repository.id}`);
      if (target) {
        return {
          providerId: repository.id,
          repositoryUrl: repository.uid,
          name: target.attributes.name,
          mode,
          targetId: target.id,
        };
      }
      return {
        providerId: repository.id,
        repositoryUrl: repository.uid,
        name: uniqueName(
          mode === TRIVY_MODE.SAST ? `${base}${SAST_NAME_SUFFIX}` : base,
          usedNames,
        ),
        mode,
      };
    });
  });
};

export const summarizeScanResults = (results: RepositoryScanResult[]) => ({
  started: results.filter((result) => result.started).length,
  failed: results.filter((result) => !result.started).length,
});
