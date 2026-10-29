import type { ReportPayload } from "@/cloudsneeker/types/reports";

export const SHARED_REPORT_STATUS = {
  OK: "ok",
  EXPIRED: "expired",
  REVOKED: "revoked",
  NOT_FOUND: "not_found",
  UNAVAILABLE: "unavailable",
} as const;

export type SharedReportStatus =
  (typeof SHARED_REPORT_STATUS)[keyof typeof SHARED_REPORT_STATUS];

export type SharedReportResult =
  | { status: typeof SHARED_REPORT_STATUS.OK; report: ReportPayload }
  | {
      status: Exclude<SharedReportStatus, typeof SHARED_REPORT_STATUS.OK>;
    };

interface ErrorBody {
  errors?: { code?: string }[];
}

interface DataBody {
  data?: { attributes?: ReportPayload };
}

const errorCode = (body: unknown): string | undefined => {
  const errors = (body as ErrorBody | null)?.errors;
  return Array.isArray(errors) ? errors[0]?.code : undefined;
};

/** Map the public `shared-reports/<token>` response to a page state. */
export const sharedReportResultFromResponse = (
  status: number,
  body: unknown,
): SharedReportResult => {
  if (status >= 200 && status < 300) {
    const report = (body as DataBody | null)?.data?.attributes;
    return report
      ? { status: SHARED_REPORT_STATUS.OK, report }
      : { status: SHARED_REPORT_STATUS.UNAVAILABLE };
  }
  if (status === 410) {
    return errorCode(body) === SHARED_REPORT_STATUS.REVOKED
      ? { status: SHARED_REPORT_STATUS.REVOKED }
      : { status: SHARED_REPORT_STATUS.EXPIRED };
  }
  if (status === 404 || status === 400) {
    return { status: SHARED_REPORT_STATUS.NOT_FOUND };
  }
  return { status: SHARED_REPORT_STATUS.UNAVAILABLE };
};

/** Token shape accepted before calling the API (urlsafe base64, bounded). */
export const isPlausibleShareToken = (token: string): boolean =>
  /^[A-Za-z0-9_-]{16,128}$/.test(token);
