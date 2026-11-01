"use server";

import { revalidatePath } from "next/cache";

import { startProviderConnectionChecks } from "@/actions/providers";
import {
  buildListingBody,
  buildProviderBody,
  buildSecretBody,
  firstErrorDetail,
  isPlanLimitError,
  parseListing,
} from "@/cloudsneeker/lib/bitbucket-import";
import {
  BITBUCKET_IMPORT_STATUS,
  type BitbucketConnection,
  type BitbucketImportRequest,
  type BitbucketImportResult,
  type BitbucketRepositoryListing,
} from "@/cloudsneeker/types/bitbucket";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError } from "@/lib/server-actions-helper";

const readJson = async (response: Response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

/** Lists the repositories a Bitbucket token can read. The token stays in the body. */
export const listBitbucketRepositories = async (
  connection: BitbucketConnection,
): Promise<BitbucketRepositoryListing | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: true });

  try {
    const response = await fetch(`${apiBaseUrl}/bitbucket/repositories`, {
      method: "POST",
      headers,
      body: JSON.stringify(buildListingBody(connection)),
    });
    const document = await readJson(response);
    if (!response.ok) {
      return {
        error: firstErrorDetail(
          document,
          "Could not list the Bitbucket repositories.",
        ),
      };
    }
    return parseListing(document ?? {});
  } catch (error) {
    return handleApiError(error);
  }
};

const importOne = async (
  repository: BitbucketImportRequest["repositories"][number],
  request: BitbucketImportRequest,
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
      buildSecretBody(
        providerId,
        repositoryUrl,
        request.accessToken,
        request.cloneUsername,
      ),
    ),
  });

  if (!secretResponse.ok) {
    const secretDocument = await readJson(secretResponse);
    // A provider without credentials cannot clone a private repository.
    await fetch(`${apiBaseUrl}/providers/${providerId}`, {
      method: "DELETE",
      headers,
    }).catch(() => undefined);
    return {
      repositoryUrl,
      status: BITBUCKET_IMPORT_STATUS.FAILED,
      message: firstErrorDetail(secretDocument, "Could not save the token."),
    };
  }

  return { repositoryUrl, status: BITBUCKET_IMPORT_STATUS.ADDED, providerId };
};

/**
 * Adds each repository as an IaC provider with the token as its credentials,
 * through the same `/providers` and `/providers/secrets` endpoints the
 * provider wizard uses. Stops at the plan's provider limit.
 */
export const importBitbucketRepositories = async (
  request: BitbucketImportRequest,
): Promise<BitbucketImportResult[] | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: true });
  const results: BitbucketImportResult[] = [];

  try {
    let limitMessage: string | undefined;
    for (const repository of request.repositories) {
      if (limitMessage) {
        results.push({
          repositoryUrl: repository.repository_url,
          status: BITBUCKET_IMPORT_STATUS.SKIPPED,
          message: limitMessage,
        });
        continue;
      }
      const { planLimit, ...result } = await importOne(
        repository,
        request,
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
    }
    return results;
  } catch (error) {
    return handleApiError(error);
  }
};
