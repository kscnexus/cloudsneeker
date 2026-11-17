/** A GitHub provider whose credential can list and clone repositories. */
export interface GithubConnection {
  id: string;
  /** GitHub user or organization login. */
  account: string;
  alias: string;
}

export interface GithubRepository {
  name: string;
  full_name: string;
  repository_url: string;
  is_private: boolean;
  is_archived: boolean;
  default_branch: string;
  updated_on: string | null;
  already_added: boolean;
}

export interface GithubRepositoryListing {
  repositories: GithubRepository[];
  truncated: boolean;
}

/** What the add action needs for one repository. */
export interface GithubRepositoryToAdd {
  full_name: string;
  repository_url: string;
}

/** How the picker sets up the scan target of each repository it adds. */
export interface GithubAddOptions {
  /** Run the new code repository target every day. */
  dailySchedule: boolean;
  /** IANA timezone the daily schedule runs in. */
  timezone: string;
}
