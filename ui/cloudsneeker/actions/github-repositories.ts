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
  buildGithubTargetBody,
  parseGithubConnections,
  parseGithubListing,
} from "@/cloudsneeker/lib/github-repositories";
import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import {
  BITBUCKET_IMPORT_STATUS,
  type BitbucketImportResult,
} from "@/cloudsneeker/types/bitbucket";
import type {
  GithubAddOptions,
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
  options: GithubAddOptions,
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

  // The target is what lists the repository in Application Security. The
  // source stays when the target cannot be created, and the row says why.
  const targetResponse = await fetch(`${apiBaseUrl}/trivy-targets`, {
    method: "POST",
    headers,
    body: JSON.stringify(
      buildGithubTargetBody(providerId, repository, options),
    ),
  });
  if (!targetResponse.ok) {
    const reason = firstErrorDetail(
      await readJson(targetResponse),
      "Could not create the scan target.",
    );
    return {
      repositoryUrl,
      status: BITBUCKET_IMPORT_STATUS.ADDED,
      providerId,
      message: `Added without a scan target: ${reason}`,
    };
  }

  return { repositoryUrl, status: BITBUCKET_IMPORT_STATUS.ADDED, providerId };
};

/**
 * Adds each repository as a repository source with no token of its own, plus
 * a code repository scan target; scans use the GitHub connection of the
 * repository's owner. Stops at the plan's provider limit.
 */
export const addGithubRepositories = async (
  repositories: GithubRepositoryToAdd[],
  options: GithubAddOptions,
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
      const { planLimit, ...result } = await addOne(
        repository,
        options,
        headers,
      );
      if (planLimit) limitMessage = result.message;
      results.push(result);
    }

    const addedIds = results.flatMap((result) =>
      result.providerId ? [result.providerId] : [],
    );
    if (addedIds.length > 0) {
      await startProviderConnectionChecks(addedIds);
      revalidatePath("/providers");
      revalidatePath(PRODUCT_ROUTE.APPLICATION_SECURITY);
    }
    return results;
  } catch (error) {
    return handleApiError(error);
  }
};
