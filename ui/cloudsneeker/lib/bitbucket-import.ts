import {
  BITBUCKET_CLONE_METHOD,
  BITBUCKET_HOST,
  type BitbucketConnection,
  type BitbucketImportRequest,
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

/** URL the provider clones: the HTTPS URL, or the SSH URL for SSH keys. */
export const cloneUrlFor = (
  repository: BitbucketImportRequest["repositories"][number],
  request: Pick<BitbucketImportRequest, "cloneMethod">,
): string =>
  request.cloneMethod === BITBUCKET_CLONE_METHOD.SSH
    ? repository.ssh_url
    : repository.repository_url;

/** IaC provider secret for one repository: the token, or the SSH key. */
export const buildCloneSecret = (
  repositoryUrl: string,
  request: Omit<BitbucketImportRequest, "repositories">,
): Record<string, string> => {
  if (request.cloneMethod === BITBUCKET_CLONE_METHOD.SSH && request.sshKey) {
    const { privateKey, passphrase, knownHosts } = request.sshKey;
    return {
      [ProviderCredentialFields.REPOSITORY_URL]: repositoryUrl,
      [ProviderCredentialFields.SSH_PRIVATE_KEY]: privateKey.trim(),
      ...(passphrase
        ? { [ProviderCredentialFields.SSH_KEY_PASSPHRASE]: passphrase }
        : {}),
      ...(knownHosts.trim()
        ? { [ProviderCredentialFields.SSH_KNOWN_HOSTS]: knownHosts.trim() }
        : {}),
    };
  }
  return {
    [ProviderCredentialFields.REPOSITORY_URL]: repositoryUrl,
    [ProviderCredentialFields.ACCESS_TOKEN]: request.accessToken,
    ...(request.cloneUsername
      ? { [ProviderCredentialFields.IAC_USERNAME]: request.cloneUsername }
      : {}),
  };
};

export const buildSecretBody = (
  providerId: string,
  secret: Record<string, string>,
) => ({
  data: {
    type: "provider-secrets",
    attributes: {
      secret_type: "static",
      secret,
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

type ImportedRepository = BitbucketImportRequest["repositories"][number];

export interface ManualRepositories {
  repositories: ImportedRepository[];
  invalid: string[];
}

const BITBUCKET_CLOUD_HOST = "bitbucket.org";
const REPOSITORY_PATH = /^[\w.-]+(\/[\w.-]+)+$/;
const SCP_SSH_URL = /^[\w.-]+@([\w.-]+):(.+)$/;

const withoutGitSuffix = (path: string) =>
  path.replace(/\/+$/, "").replace(/\.git$/, "");

const fromHostPath = (
  host: string,
  path: string,
  sshUrl: string,
): ImportedRepository | null => {
  const fullName = withoutGitSuffix(path.replace(/^\/+/, ""));
  if (!REPOSITORY_PATH.test(fullName)) return null;
  return {
    full_name: fullName,
    repository_url: `https://${host}/${fullName}.git`,
    ssh_url: sshUrl,
  };
};

const cloudRepository = (fullName: string) =>
  fromHostPath(
    BITBUCKET_CLOUD_HOST,
    fullName,
    `git@${BITBUCKET_CLOUD_HOST}:${withoutGitSuffix(fullName)}.git`,
  );

const parseManualEntry = (
  entry: string,
  workspace: string,
): ImportedRepository | null => {
  const scp = entry.match(SCP_SSH_URL);
  if (scp) {
    const [, host, path] = scp;
    return fromHostPath(host, path, `${withoutGitSuffix(entry)}.git`);
  }
  if (/^(ssh|https):\/\//i.test(entry)) {
    let url: URL;
    try {
      url = new URL(entry);
    } catch {
      return null;
    }
    if (url.protocol === "ssh:") {
      return fromHostPath(url.hostname, url.pathname, entry);
    }
    // Only Bitbucket Cloud links map to a known SSH URL; extra path parts
    // such as /src/main are dropped.
    return url.hostname === BITBUCKET_CLOUD_HOST
      ? cloudRepository(
          url.pathname.split("/").filter(Boolean).slice(0, 2).join("/"),
        )
      : null;
  }
  const path = entry.includes("/") ? entry : `${workspace.trim()}/${entry}`;
  return cloudRepository(path);
};

/**
 * Repositories typed by hand for an SSH-key import: `workspace/repo`, a bare
 * `repo` in the given workspace, a Bitbucket Cloud link, or an SSH clone URL.
 */
export const parseManualRepositories = (
  text: string,
  workspace: string,
): ManualRepositories => {
  const repositories = new Map<string, ImportedRepository>();
  const invalid: string[] = [];
  for (const entry of text.split(/[\s,]+/).filter(Boolean)) {
    const repository = parseManualEntry(entry, workspace);
    if (repository) repositories.set(repository.repository_url, repository);
    else invalid.push(entry);
  }
  return { repositories: Array.from(repositories.values()), invalid };
};
