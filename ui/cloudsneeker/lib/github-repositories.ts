import { SCAN_ALL_REPO_PROFILE } from "@/cloudsneeker/lib/app-security-scan-all";
import type {
  GithubAddOptions,
  GithubConnection,
  GithubRepository,
  GithubRepositoryListing,
  GithubRepositoryToAdd,
} from "@/cloudsneeker/types/github-repositories";
import { TRIVY_MODE } from "@/cloudsneeker/types/trivy";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

interface ListingResource {
  attributes?: GithubRepository;
}

interface ListingMeta {
  truncated?: boolean;
}

interface ListingDocument {
  data?: ListingResource[];
  meta?: ListingMeta;
}

export const parseGithubListing = (
  document: ListingDocument,
): GithubRepositoryListing => ({
  repositories: (document.data ?? [])
    .map((resource) => resource.attributes)
    .filter((repository): repository is GithubRepository =>
      Boolean(repository?.repository_url),
    ),
  truncated: Boolean(document.meta?.truncated),
});

interface ProviderAttributes {
  uid?: string;
  alias?: string | null;
}

interface ProviderResource {
  id: string;
  attributes?: ProviderAttributes;
}

interface ProvidersDocument {
  data?: ProviderResource[];
}

export const parseGithubConnections = (
  document: ProvidersDocument,
): GithubConnection[] =>
  (document.data ?? [])
    .filter((provider) => provider.attributes?.uid)
    .map((provider) => ({
      id: provider.id,
      account: provider.attributes?.uid ?? "",
      alias: provider.attributes?.alias ?? "",
    }));

/**
 * Secret of a repository source that has no token of its own: scans borrow
 * one from the GitHub connection of the repository's owner.
 */
export const buildConnectionSecret = (
  repositoryUrl: string,
): Record<string, string> => ({
  [ProviderCredentialFields.REPOSITORY_URL]: repositoryUrl,
});

export const connectionLabel = (connection: GithubConnection): string =>
  connection.alias && connection.alias !== connection.account
    ? `${connection.account} (${connection.alias})`
    : connection.account;

export const filterGithubRepositories = (
  repositories: GithubRepository[],
  query: string,
): GithubRepository[] => {
  const needle = query.trim().toLowerCase();
  if (!needle) return repositories;
  return repositories.filter((repository) =>
    repository.full_name.toLowerCase().includes(needle),
  );
};

/** Repositories the picker selects by default: not added, not archived. */
export const defaultGithubSelection = (
  repositories: GithubRepository[],
): Set<string> =>
  new Set(
    repositories
      .filter(
        (repository) => !repository.already_added && !repository.is_archived,
      )
      .map((repository) => repository.repository_url),
  );

/** Daily schedule of a picked repository's scan target: 02:00. */
export const GITHUB_DAILY_SCAN_CRON = "0 2 * * *";

/**
 * Code repository target of a picked repository, so it shows in Application
 * Security as soon as it is added.
 */
export const buildGithubTargetBody = (
  providerId: string,
  repository: GithubRepositoryToAdd,
  options: GithubAddOptions,
) => ({
  data: {
    type: "cloudsneeker-trivy-targets",
    attributes: {
      name: repository.full_name,
      description: "Added from GitHub repositories.",
      mode: TRIVY_MODE.REPO,
      provider_id: providerId,
      config: {
        repository_url: repository.repository_url,
        profile: SCAN_ALL_REPO_PROFILE,
      },
      schedule_enabled: options.dailySchedule,
      schedule_cron: options.dailySchedule ? GITHUB_DAILY_SCAN_CRON : "",
      schedule_timezone: options.timezone || "UTC",
    },
  },
});
