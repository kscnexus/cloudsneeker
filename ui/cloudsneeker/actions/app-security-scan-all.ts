"use server";

import { revalidatePath } from "next/cache";

import {
  planRepositoryScans,
  type RepositoryScanItem,
  type RepositoryScanResult,
  type RepositorySource,
} from "@/cloudsneeker/lib/app-security-scan-all";
import { firstErrorDetail } from "@/cloudsneeker/lib/bitbucket-import";
import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import {
  TRIVY_MODE,
  type TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError } from "@/lib/server-actions-helper";

const PAGE_SIZE = 100;
/** Stops a runaway listing; 50 pages is 5,000 repositories. */
const MAX_PAGES = 50;

interface ListDocument<T> {
  data?: T[];
  meta?: { pagination?: { pages?: number } };
  errors?: { detail?: string; code?: string }[];
}

const readJson = async (response: Response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

/** Every page of a JSON:API list, or an error message. */
const listAll = async <T>(
  path: string,
  params: Record<string, string>,
  headers: Record<string, string>,
  failure: string,
): Promise<T[] | { error: string }> => {
  const items: T[] = [];
  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const url = new URL(`${apiBaseUrl}${path}`);
    for (const [key, value] of Object.entries(params)) {
      url.searchParams.append(key, value);
    }
    url.searchParams.append("page[size]", String(PAGE_SIZE));
    url.searchParams.append("page[number]", String(page));
    const response = await fetch(url.toString(), { headers });
    const document: ListDocument<T> | null = await readJson(response);
    if (!response.ok) return { error: firstErrorDetail(document, failure) };
    items.push(...(document?.data ?? []));
    const pages = document?.meta?.pagination?.pages ?? 1;
    if (page >= pages) break;
  }
  return items;
};

interface ProviderResource {
  id: string;
  attributes: { uid?: string; alias?: string | null };
}

/**
 * Every connected repository (IaC provider) and whether it already has a
 * code repository target. Nothing is created yet.
 */
export const planScanAllRepositories = async (): Promise<
  { items: RepositoryScanItem[] } | { error: string }
> => {
  const headers = await getAuthHeaders({ contentType: false });
  try {
    const [providers, targets] = await Promise.all([
      listAll<ProviderResource>(
        "/providers",
        { "filter[provider]": "iac" },
        headers,
        "Could not load the connected repositories.",
      ),
      listAll<TrivyTargetResource>(
        "/trivy-targets",
        { sort: "inserted_at" },
        headers,
        "Could not load the scan targets.",
      ),
    ]);
    if ("error" in providers) return providers;
    if ("error" in targets) return targets;

    const repositories: RepositorySource[] = providers
      .filter((provider) => provider.attributes.uid)
      .map((provider) => ({
        id: provider.id,
        uid: provider.attributes.uid ?? "",
        alias: provider.attributes.alias,
      }));
    return { items: planRepositoryScans(repositories, targets) };
  } catch (error) {
    return handleApiError(error);
  }
};

const createRepoTarget = async (
  item: RepositoryScanItem,
  headers: Record<string, string>,
): Promise<{ targetId: string } | { error: string }> => {
  const response = await fetch(`${apiBaseUrl}/trivy-targets`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      data: {
        type: "cloudsneeker-trivy-targets",
        attributes: {
          name: item.name,
          description: "Added by Scan all repositories.",
          mode: TRIVY_MODE.REPO,
          provider_id: item.providerId,
          // Scanners stay empty so the mode's defaults apply.
          config: { repository_url: item.repositoryUrl },
          schedule_enabled: false,
          schedule_cron: "",
          schedule_timezone: "UTC",
        },
      },
    }),
  });
  const document = await readJson(response);
  if (!response.ok || !document?.data?.id) {
    return {
      error: firstErrorDetail(document, "Could not create the scan target."),
    };
  }
  return { targetId: String(document.data.id) };
};

const startScan = async (
  targetId: string,
  headers: Record<string, string>,
): Promise<string | null> => {
  const response = await fetch(`${apiBaseUrl}/trivy-targets/${targetId}/scan`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      data: { type: "cloudsneeker-trivy-runs", attributes: {} },
    }),
  });
  if (response.ok) return null;
  return firstErrorDetail(
    await readJson(response),
    "Could not start the scan.",
  );
};

/** Creates missing targets and starts one code repository scan per item. */
export const scanRepositoryBatch = async (
  items: RepositoryScanItem[],
): Promise<RepositoryScanResult[] | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: true });
  const results: RepositoryScanResult[] = [];
  try {
    for (const item of items) {
      let targetId = item.targetId;
      if (!targetId) {
        const created = await createRepoTarget(item, headers);
        if ("error" in created) {
          results.push({
            providerId: item.providerId,
            name: item.name,
            started: false,
            message: created.error,
          });
          continue;
        }
        targetId = created.targetId;
      }
      const failure = await startScan(targetId, headers);
      results.push({
        providerId: item.providerId,
        name: item.name,
        started: failure === null,
        ...(failure ? { message: failure } : {}),
      });
    }
    revalidatePath(PRODUCT_ROUTE.APPLICATION_SECURITY);
    return results;
  } catch (error) {
    return handleApiError(error);
  }
};
