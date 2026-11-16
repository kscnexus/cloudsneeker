"use server";

import { revalidatePath } from "next/cache";

import { startProviderConnectionChecks } from "@/actions/providers";
import {
  buildProviderBody,
  buildSecretBody,
  firstErrorDetail,
  isPlanLimitError,
} from "@/cloudsneeker/lib/bitbucket-import";
import {
  buildConnectionSecret,
  parseGithubConnections,
  parseGithubListing,
} from "@/cloudsneeker/lib/github-repositories";
import {
  BITBUCKET_IMPORT_STATUS,
  type BitbucketImportResult,
} from "@/cloudsneeker/types/bitbucket";
import type {
  GithubConnection,
  GithubRepositoryListing,
  GithubRepositoryToAdd,
} from "@/cloudsneeker/types/github-repositories";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError } from "@/lib/server-actions-helper";

const readJson = async (response: Response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

/** GitHub providers of the tenant; each can list its account's repositories. */
export const getGithubConnections = async (): Promise<GithubConnection[]> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/providers`);
  url.searchParams.set("filter[provider__in]", "github");
  url.searchParams.set("page[size]", "100");

  try {
    const response = await fetch(url.toString(), { headers });
    if (!response.ok) return [];
    return parseGithubConnections((await readJson(response)) ?? {});
  } catch {
    return [];
  }
};

/** Lists the repositories a GitHub connection can read. */
export const listGithubRepositories = async (
  connectionId: string,
): Promise<GithubRepositoryListing | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const response = await fetch(
      `${apiBaseUrl}/github/providers/${encodeURIComponent(connectionId)}/repositories`,
      { headers },
    );
    const document = await readJson(response);
    if (!response.ok) {
      return {
        error: firstErrorDetail(
          document,
          "Could not list the GitHub repositories.",
        ),
      };
    }
    return parseGithubListing(document ?? {});
  } catch (error) {
    return handleApiError(error);
  }
};

const addOne = async (
  repository: GithubRepositoryToAdd,
  headers: Record<string, string>,
): Promise<BitbucketImportResult & { planLimit?: boolean }> => {
  const repositoryUrl = repository.repository_url;
  const providerResponse = await fetch(`${apiBaseUrl}/providers`, {
    method: "POST",
    headers,
    body: JSON.stringify(
      buildProviderBody(repositoryUrl, repository.full_name),
    ),
  });
  const providerDocument = await readJson(providerResponse);

  if (providerResponse.status === 409) {
    return { repositoryUrl, status: BITBUCKET_IMPORT_STATUS.EXISTS };
  }
  if (!providerResponse.ok) {
    return {
      repositoryUrl,
      status: BITBUCKET_IMPORT_STATUS.FAILED,
      message: firstErrorDetail(
        providerDocument,
        "Could not add the provider.",
      ),
      planLimit: isPlanLimitError(providerDocument),
    };
  }

  const providerId: string = providerDocument?.data?.id;
  const secretResponse = await fetch(`${apiBaseUrl}/providers/secrets`, {
    method: "POST",
    headers,
    body: JSON.stringify(
      buildSecretBody(providerId, buildConnectionSecret(repositoryUrl)),
    ),
  });

  if (!secretResponse.ok) {
    const secretDocument = await readJson(secretResponse);
    await fetch(`${apiBaseUrl}/providers/${providerId}`, {
      method: "DELETE",
      headers,
    }).catch(() => undefined);
    return {
      repositoryUrl,
      status: BITBUCKET_IMPORT_STATUS.FAILED,
      message: firstErrorDetail(secretDocument, "Could not save the source."),
    };
  }

  return { repositoryUrl, status: BITBUCKET_IMPORT_STATUS.ADDED, providerId };
};

/**
 * Adds each repository as an Infrastructure as Code provider with no token of
 * its own; scans use the GitHub connection of the repository's owner. Stops
 * at the plan's provider limit.
 */
export const addGithubRepositories = async (
  repositories: GithubRepositoryToAdd[],
): Promise<BitbucketImportResult[] | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: true });
  const results: BitbucketImportResult[] = [];

  try {
    let limitMessage: string | undefined;
    for (const repository of repositories) {
      if (limitMessage) {
        results.push({
          repositoryUrl: repository.repository_url,
          status: BITBUCKET_IMPORT_STATUS.SKIPPED,
          message: limitMessage,
        });
        continue;
      }
      const { planLimit, ...result } = await addOne(repository, headers);
      if (planLimit) limitMessage = result.message;
      results.push(result);
    }

    const addedIds = results.flatMap((result) =>
      result.providerId ? [result.providerId] : [],
    );
    if (addedIds.length > 0) {
      await startProviderConnectionChecks(addedIds);
      revalidatePath("/providers");
    }
    return results;
  } catch (error) {
    return handleApiError(error);
  }
};
