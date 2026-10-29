import { REPORT_FORMAT, type ReportFormat } from "@/cloudsneeker/types/reports";

const DOWNLOADABLE_FORMATS = new Set<string>(Object.values(REPORT_FORMAT));

export const isDownloadableReportFormat = (
  value: string,
): value is ReportFormat => DOWNLOADABLE_FORMATS.has(value);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const isReportRunId = (value: string): boolean => UUID.test(value);

const COPY_RESPONSE_HEADERS = [
  "content-type",
  "content-length",
  "content-disposition",
  "etag",
  "last-modified",
] as const;

const FALLBACK_CONTENT_TYPE: Record<ReportFormat, string> = {
  pdf: "application/pdf",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  csv: "text/csv",
  json: "application/json",
};

export const buildReportDownloadHeaders = (
  upstream: Headers,
  runId: string,
  format: ReportFormat,
): Headers => {
  const headers = new Headers({ "Cache-Control": "no-store" });
  for (const name of COPY_RESPONSE_HEADERS) {
    const value = upstream.get(name);
    if (value) headers.set(name, value);
  }
  if (!headers.has("content-type")) {
    headers.set("content-type", FALLBACK_CONTENT_TYPE[format]);
  }
  if (!headers.has("content-disposition")) {
    headers.set(
      "content-disposition",
      `attachment; filename="report-${runId}.${format}"`,
    );
  }
  return headers;
};
