export const BITBUCKET_HOST = {
  CLOUD: "cloud",
  SERVER: "server",
} as const;

export type BitbucketHost =
  (typeof BITBUCKET_HOST)[keyof typeof BITBUCKET_HOST];

export interface BitbucketConnection {
  host: BitbucketHost;
  /** Cloud workspace ID, or Server project key (optional on Server). */
  workspace: string;
  accessToken: string;
  /** Atlassian account email (Cloud API token) or Server user name. */
  username: string;
  serverUrl: string;
}

export interface BitbucketRepository {
  name: string;
  full_name: string;
  repository_url: string;
  html_url: string;
  /** SSH clone URL; empty when Bitbucket does not offer SSH for the repository. */
  ssh_url: string;
  project: string;
  is_private: boolean;
  updated_on: string | null;
  already_added: boolean;
}

export interface BitbucketRepositoryListing {
  repositories: BitbucketRepository[];
  cloneUsername: string;
  truncated: boolean;
}

export const BITBUCKET_IMPORT_STATUS = {
  ADDED: "added",
  EXISTS: "exists",
  FAILED: "failed",
  SKIPPED: "skipped",
} as const;

export type BitbucketImportStatus =
  (typeof BITBUCKET_IMPORT_STATUS)[keyof typeof BITBUCKET_IMPORT_STATUS];

export interface BitbucketImportResult {
  repositoryUrl: string;
  status: BitbucketImportStatus;
  providerId?: string;
  message?: string;
}

export const BITBUCKET_CLONE_METHOD = {
  TOKEN: "token",
  SSH: "ssh",
} as const;

export type BitbucketCloneMethod =
  (typeof BITBUCKET_CLONE_METHOD)[keyof typeof BITBUCKET_CLONE_METHOD];

export interface BitbucketSshKey {
  privateKey: string;
  passphrase: string;
  /** Host key lines for Bitbucket Data Center / Server. */
  knownHosts: string;
}

export interface BitbucketImportRequest {
  repositories: Pick<
    BitbucketRepository,
    "repository_url" | "ssh_url" | "full_name"
  >[];
  cloneMethod: BitbucketCloneMethod;
  accessToken: string;
  cloneUsername: string;
  sshKey?: BitbucketSshKey;
}
