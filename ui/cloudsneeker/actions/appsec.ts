"use server";

import { revalidatePath } from "next/cache";

import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

type SearchParams = Record<string, string | undefined>;
type Attributes = Record<string, unknown>;

const AREA = PRODUCT_ROUTE.APPLICATION_SECURITY;

const buildUrl = (path: string, searchParams?: SearchParams): string => {
  const url = new URL(`${apiBaseUrl}${path}`);
  for (const [key, value] of Object.entries(searchParams ?? {})) {
    if (value !== undefined && value !== "") {
      url.searchParams.append(key, value);
    }
  }
  return url.toString();
};

const read = async (path: string, searchParams?: SearchParams) => {
  const headers = await getAuthHeaders({ contentType: false });
  try {
    const response = await fetch(buildUrl(path, searchParams), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

const write = async (
  method: "POST" | "PATCH" | "DELETE",
  path: string,
  type: string,
  attributes?: Attributes,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  try {
    const response = await fetch(buildUrl(path), {
      method,
      headers,
      body: attributes
        ? JSON.stringify({ data: { type, attributes } })
        : undefined,
    });
    const result = await handleApiResponse(response);
    revalidatePath(AREA, "layout");
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

const id = (value: string) => encodeURIComponent(value);

// --- Overview, capabilities, engine, settings ---

export const getAppSecOverview = async (days?: string) =>
  read("/appsec/overview", { days });

export const getAppSecCapabilities = async () => read("/appsec/capabilities");

export const getAppSecEngine = async () => read("/appsec/engine");

export const getAppSecSettings = async () => read("/appsec/settings");

export const updateAppSecSettings = async (attributes: Attributes) =>
  write(
    "PATCH",
    "/appsec/settings",
    "cloudsneeker-appsec-settings",
    attributes,
  );

// --- Findings ---

export const listAppSecFindings = async (searchParams?: SearchParams) =>
  read("/appsec-findings", searchParams);

export const getAppSecFinding = async (findingId: string) =>
  read(`/appsec-findings/${id(findingId)}`);

export const getAppSecFindingsSummary = async (searchParams?: SearchParams) =>
  read("/appsec-findings/summary", searchParams);

// --- Applications ---

export const listAppSecApplications = async (searchParams?: SearchParams) =>
  read("/appsec-applications", searchParams);

export const getAppSecApplication = async (applicationId: string) =>
  read(`/appsec-applications/${id(applicationId)}`);

export const createAppSecApplication = async (attributes: Attributes) =>
  write(
    "POST",
    "/appsec-applications",
    "cloudsneeker-appsec-applications",
    attributes,
  );

export const updateAppSecApplication = async (
  applicationId: string,
  attributes: Attributes,
) =>
  write(
    "PATCH",
    `/appsec-applications/${id(applicationId)}`,
    "cloudsneeker-appsec-applications",
    attributes,
  );

export const deleteAppSecApplication = async (applicationId: string) =>
  write(
    "DELETE",
    `/appsec-applications/${id(applicationId)}`,
    "cloudsneeker-appsec-applications",
  );

// --- Scan profiles ---

export const listAppSecProfiles = async () => read("/appsec-scan-profiles");

export const createAppSecProfile = async (attributes: Attributes) =>
  write(
    "POST",
    "/appsec-scan-profiles",
    "cloudsneeker-appsec-scan-profiles",
    attributes,
  );

export const updateAppSecProfile = async (
  profileId: string,
  attributes: Attributes,
) =>
  write(
    "PATCH",
    `/appsec-scan-profiles/${id(profileId)}`,
    "cloudsneeker-appsec-scan-profiles",
    attributes,
  );

export const deleteAppSecProfile = async (profileId: string) =>
  write(
    "DELETE",
    `/appsec-scan-profiles/${id(profileId)}`,
    "cloudsneeker-appsec-scan-profiles",
  );

// --- Policies ---

export const listAppSecPolicies = async (searchParams?: SearchParams) =>
  read("/appsec-policies", searchParams);

export const getAppSecPolicy = async (policyId: string) =>
  read(`/appsec-policies/${id(policyId)}`);

export const validateAppSecPolicy = async (kind: string, content: string) =>
  write("POST", "/appsec-policies/validate", "cloudsneeker-appsec-policies", {
    kind,
    content,
  });

export const createAppSecPolicy = async (attributes: Attributes) =>
  write("POST", "/appsec-policies", "cloudsneeker-appsec-policies", attributes);

export const updateAppSecPolicy = async (
  policyId: string,
  attributes: Attributes,
) =>
  write(
    "PATCH",
    `/appsec-policies/${id(policyId)}`,
    "cloudsneeker-appsec-policies",
    attributes,
  );

export const deleteAppSecPolicy = async (policyId: string) =>
  write(
    "DELETE",
    `/appsec-policies/${id(policyId)}`,
    "cloudsneeker-appsec-policies",
  );

// --- SBOMs and components ---

export const listAppSecSboms = async (searchParams?: SearchParams) =>
  read("/appsec-sboms", searchParams);

export const getAppSecSbom = async (sbomId: string) =>
  read(`/appsec-sboms/${id(sbomId)}`);

export const listAppSecSbomComponents = async (
  sbomId: string,
  searchParams?: SearchParams,
) => read(`/appsec-sboms/${id(sbomId)}/components`, searchParams);

export const compareAppSecSboms = async (headId: string, baseId: string) =>
  read(`/appsec-sboms/${id(headId)}/compare`, { base: baseId });

export const listAppSecComponents = async (searchParams?: SearchParams) =>
  read("/appsec-components", searchParams);

export const getAppSecComponentsSummary = async (searchParams?: SearchParams) =>
  read("/appsec-components/summary", searchParams);

// --- Scans ---

export const cancelAppSecScan = async (runId: string) =>
  write(
    "POST",
    `/trivy-runs/${id(runId)}/cancel`,
    "cloudsneeker-trivy-runs",
    {},
  );
