import {
  BITBUCKET_HOST,
  type BitbucketConnection,
  type BitbucketRepository,
  type BitbucketRepositoryListing,
} from "@/cloudsneeker/types/bitbucket";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

/** Repositories created per server action call, so each call stays short. */
export const BITBUCKET_IMPORT_BATCH_SIZE = 10;

const ALIAS_MIN_LENGTH = 3;
const ALIAS_MAX_LENGTH = 100;

export const PLAN_LIMIT_REACHED_CODE = "plan_limit_reached";

/** Provider alias from the repository's full name (the API allows 3-100 chars). */
export const repositoryAlias = (fullName: string): string | undefined => {
  const alias = fullName.trim().slice(0, ALIAS_MAX_LENGTH);
  return alias.length >= ALIAS_MIN_LENGTH ? alias : undefined;
};

export const buildListingBody = (connection: BitbucketConnection) => ({
  data: {
    type: "bitbucket-repository-listings",
    attributes: {
      access_token: connection.accessToken.trim(),
      workspace: connection.workspace.trim(),
      username: connection.username.trim(),
      server_url:
        connection.host === BITBUCKET_HOST.SERVER
          ? connection.serverUrl.trim()
          : "",
    },
  },
});

interface ListingDocument {
  data?: { attributes?: BitbucketRepository }[];
  meta?: { clone_username?: string; truncated?: boolean };
}

export const parseListing = (
  document: ListingDocument,
): BitbucketRepositoryListing => ({
  repositories: (document.data ?? [])
    .map((resource) => resource.attributes)
    .filter((repository): repository is BitbucketRepository =>
      Boolean(repository?.repository_url),
    ),
  cloneUsername: document.meta?.clone_username ?? "",
  truncated: Boolean(document.meta?.truncated),
});

export const buildProviderBody = (repositoryUrl: string, fullName: string) => {
  const alias = repositoryAlias(fullName);
  return {
    data: {
      type: "providers",
      attributes: {
        provider: "iac",
        uid: repositoryUrl,
        ...(alias ? { alias } : {}),
      },
    },
  };
};

export const buildSecretBody = (
  providerId: string,
  repositoryUrl: string,
  accessToken: string,
  cloneUsername: string,
) => ({
  data: {
    type: "provider-secrets",
    attributes: {
      secret_type: "static",
      secret: {
        [ProviderCredentialFields.REPOSITORY_URL]: repositoryUrl,
        [ProviderCredentialFields.ACCESS_TOKEN]: accessToken,
        ...(cloneUsername
          ? { [ProviderCredentialFields.IAC_USERNAME]: cloneUsername }
          : {}),
      },
    },
    relationships: {
      provider: { data: { id: providerId, type: "providers" } },
    },
  },
});

interface ErrorDocument {
  errors?: { detail?: string; code?: string }[];
  detail?: string;
}

export const firstErrorDetail = (
  document: ErrorDocument | null,
  fallback: string,
): string => document?.errors?.[0]?.detail || document?.detail || fallback;

export const isPlanLimitError = (document: ErrorDocument | null): boolean =>
  Boolean(
    document?.errors?.some((error) => error.code === PLAN_LIMIT_REACHED_CODE),
  );

/** Repositories not yet added, which the picker selects by default. */
export const defaultSelection = (
  repositories: BitbucketRepository[],
): Set<string> =>
  new Set(
    repositories
      .filter((repository) => !repository.already_added)
      .map((repository) => repository.repository_url),
  );

export const filterRepositories = (
  repositories: BitbucketRepository[],
  query: string,
): BitbucketRepository[] => {
  const needle = query.trim().toLowerCase();
  if (!needle) return repositories;
  return repositories.filter((repository) =>
    [repository.full_name, repository.project].some((value) =>
      value.toLowerCase().includes(needle),
    ),
  );
};

export const chunk = <T>(items: T[], size: number): T[][] => {
  const chunks: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }
  return chunks;
};
