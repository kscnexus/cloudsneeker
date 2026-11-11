// Upstream API URL for an Application Security download. The same-origin
// proxy (`app/api/cloudsneeker/appsec/download`) forwards the session token;
// this module decides what the browser may ask for.

import { APPSEC_DOWNLOAD_KIND } from "@/cloudsneeker/lib/appsec";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const FORMATS: Record<string, readonly string[]> = {
  [APPSEC_DOWNLOAD_KIND.SBOM]: ["cyclonedx", "spdx-json"],
  [APPSEC_DOWNLOAD_KIND.SCAN]: ["json", "sarif", "cyclonedx", "spdx-json"],
  [APPSEC_DOWNLOAD_KIND.FINDINGS]: ["csv", "json"],
};

/** Finding filters the export accepts; anything else is dropped. */
const FINDING_QUERY_KEY = /^(sort|filter\[[a-z_]+\])$/;

export interface AppSecDownloadTarget {
  /** Path and query under the API base URL. */
  path: string;
  fallbackName: string;
}

export const APPSEC_DOWNLOAD_ERROR = {
  KIND: "Unknown download.",
  FORMAT: "Unknown format.",
  ID: "Unknown item.",
} as const;

/**
 * Resolve the browser's query to an API path.
 *
 * @returns The target, or an error message for a request that is not allowed.
 */
export const resolveAppSecDownload = (
  params: URLSearchParams,
): AppSecDownloadTarget | string => {
  const kind = params.get("kind") ?? "";
  const format = (params.get("format") ?? "").toLowerCase();
  const formats = FORMATS[kind];
  if (!formats) return APPSEC_DOWNLOAD_ERROR.KIND;
  if (!formats.includes(format)) return APPSEC_DOWNLOAD_ERROR.FORMAT;

  if (kind === APPSEC_DOWNLOAD_KIND.FINDINGS) {
    const query = new URLSearchParams({ format });
    params.forEach((value, key) => {
      if (FINDING_QUERY_KEY.test(key)) query.set(key, value);
    });
    return {
      path: `/appsec-findings/export?${query.toString()}`,
      fallbackName: `findings.${format}`,
    };
  }

  const id = params.get("id") ?? "";
  if (!UUID.test(id)) return APPSEC_DOWNLOAD_ERROR.ID;
  const query = new URLSearchParams({ format });
  if (kind === APPSEC_DOWNLOAD_KIND.SCAN) {
    const index = params.get("index") ?? "";
    if (/^\d{1,3}$/.test(index)) query.set("index", index);
    return {
      path: `/trivy-runs/${id}/export?${query.toString()}`,
      fallbackName: `scan-${id}.${format === "json" ? "json" : `${format}.json`}`,
    };
  }
  return {
    path: `/appsec-sboms/${id}/download?${query.toString()}`,
    fallbackName: `sbom-${id}.${format}.json`,
  };
};

const COPY_RESPONSE_HEADERS = [
  "content-type",
  "content-length",
  "content-disposition",
] as const;

export const buildAppSecDownloadHeaders = (
  upstream: Headers,
  fallbackName: string,
): Headers => {
  const headers = new Headers({ "Cache-Control": "no-store" });
  for (const name of COPY_RESPONSE_HEADERS) {
    const value = upstream.get(name);
    if (value) headers.set(name, value);
  }
  if (!headers.has("content-type")) {
    headers.set("content-type", "application/octet-stream");
  }
  if (!headers.has("content-disposition")) {
    headers.set(
      "content-disposition",
      `attachment; filename="${fallbackName}"`,
    );
  }
  return headers;
};
