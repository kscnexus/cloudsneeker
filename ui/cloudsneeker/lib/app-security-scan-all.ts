import {
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

/** One repository to scan; without `targetId` a code repository target is created first. */
export interface RepositoryScanItem {
  providerId: string;
  repositoryUrl: string;
  name: string;
  targetId?: string;
}

export interface RepositoryScanResult {
  providerId: string;
  name: string;
  started: boolean;
  message?: string;
}

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
 * What "Scan all repositories" does for each connected repository: rescan
 * its code repository target, or create one (named after the repository)
 * and scan it.
 */
export const planRepositoryScans = (
  repositories: RepositorySource[],
  targets: TrivyTargetResource[],
): RepositoryScanItem[] => {
  const usedNames = new Set(targets.map((target) => target.attributes.name));
  const repoTargets = new Map<string, TrivyTargetResource>();
  for (const target of targets) {
    if (
      target.attributes.mode === TRIVY_MODE.REPO &&
      !repoTargets.has(target.attributes.provider_id)
    ) {
      repoTargets.set(target.attributes.provider_id, target);
    }
  }

  return repositories.map((repository) => {
    const existing = repoTargets.get(repository.id);
    if (existing) {
      return {
        providerId: repository.id,
        repositoryUrl: repository.uid,
        name: existing.attributes.name,
        targetId: existing.id,
      };
    }
    const base =
      repository.alias?.trim() || repositoryNameFromUrl(repository.uid);
    return {
      providerId: repository.id,
      repositoryUrl: repository.uid,
      name: uniqueName(base, usedNames),
    };
  });
};

export const summarizeScanResults = (results: RepositoryScanResult[]) => ({
  started: results.filter((result) => result.started).length,
  failed: results.filter((result) => !result.started).length,
});
