import type {
  RepositoryBranchList,
  RepositoryBranchResource,
} from "@/cloudsneeker/types/trivy";

/** One target to create: its name and the branch it scans ("" = default). */
export interface BranchTarget {
  name: string;
  branch: string;
}

/**
 * Target name with the branch it scans, as the API labels reports
 * (`branch_label` in `services/repo_branches.py`).
 */
export const branchTargetName = (name: string, branch: string): string => {
  const trimmed = branch.trim();
  if (!trimmed) return name;
  const lower = name.toLowerCase();
  if (
    lower.endsWith(`@ ${trimmed}`.toLowerCase()) ||
    lower.endsWith(`(${trimmed})`.toLowerCase())
  ) {
    return name;
  }
  return `${name} @ ${trimmed}`;
};

/**
 * Targets a create form saves: one per selected branch. With one branch (or
 * none, the default branch) the name is kept; with several each name gets
 * its branch so the names stay unique.
 */
export const targetsForBranches = (
  name: string,
  branches: readonly string[],
): BranchTarget[] => {
  const unique = Array.from(
    new Set(branches.map((branch) => branch.trim()).filter(Boolean)),
  );
  if (unique.length === 0) return [{ name, branch: "" }];
  if (unique.length === 1) return [{ name, branch: unique[0] }];
  return unique.map((branch) => ({
    name: branchTargetName(name, branch),
    branch,
  }));
};

/** How a target's branch reads in lists and details. */
export const branchDisplay = (branch?: string | null): string =>
  branch?.trim() ? branch.trim() : "Default branch";

/** Branch list from the `/appsec/repository-branches` response. */
export const toRepositoryBranchList = (
  response: unknown,
): RepositoryBranchList | null => {
  if (!response || typeof response !== "object") return null;
  const body = response as {
    data?: unknown;
    meta?: { default_branch?: unknown; truncated?: unknown };
  };
  if (!Array.isArray(body.data)) return null;
  const branches = (body.data as RepositoryBranchResource[])
    .map((item) => item?.attributes?.name)
    .filter((name): name is string => typeof name === "string" && !!name);
  const defaultBranch =
    typeof body.meta?.default_branch === "string"
      ? body.meta.default_branch
      : "";
  return {
    branches,
    defaultBranch,
    truncated: body.meta?.truncated === true,
  };
};

/** Status line after asking the API to record target branches. */
export const recordBranchesMessage = (result: unknown): string => {
  if (!result || typeof result !== "object") {
    return "Branches could not be recorded.";
  }
  if ("error" in result && (result as { error?: unknown }).error) {
    return String((result as { error: unknown }).error);
  }
  const attributes = (
    result as { data?: { attributes?: { targets?: unknown } } }
  ).data?.attributes;
  const count =
    typeof attributes?.targets === "number" ? attributes.targets : 0;
  if (count === 0) return "Every repository target already names its branch.";
  return `Recording the branch of ${count} ${count === 1 ? "target" : "targets"} in the background. Refresh in a few minutes.`;
};
