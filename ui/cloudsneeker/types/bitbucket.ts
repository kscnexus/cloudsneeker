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

export interface BitbucketImportRequest {
  repositories: Pick<BitbucketRepository, "repository_url" | "full_name">[];
  accessToken: string;
  cloneUsername: string;
}
