import { describe, expect, it } from "vitest";

import { EXECUTIVE_REPORT_FIXTURE } from "@/cloudsneeker/components/report-view.fixture";
import {
  isPlausibleShareToken,
  SHARED_REPORT_STATUS,
  sharedReportResultFromResponse,
} from "@/cloudsneeker/lib/shared-report";

const errorBody = (code: string) => ({
  errors: [{ detail: "x", code, status: "410" }],
});

describe("sharedReportResultFromResponse", () => {
  it("returns the report payload on success", () => {
    expect(
      sharedReportResultFromResponse(200, {
        data: {
          type: "cloudsneeker-shared-reports",
          id: "shared",
          attributes: EXECUTIVE_REPORT_FIXTURE,
        },
      }),
    ).toEqual({
      status: SHARED_REPORT_STATUS.OK,
      report: EXECUTIVE_REPORT_FIXTURE,
    });
  });

  it("maps 410 to expired or revoked", () => {
    expect(sharedReportResultFromResponse(410, errorBody("expired"))).toEqual({
      status: SHARED_REPORT_STATUS.EXPIRED,
    });
    expect(sharedReportResultFromResponse(410, errorBody("revoked"))).toEqual({
      status: SHARED_REPORT_STATUS.REVOKED,
    });
    expect(sharedReportResultFromResponse(410, null)).toEqual({
      status: SHARED_REPORT_STATUS.EXPIRED,
    });
  });

  it("maps unknown tokens and failures", () => {
    expect(sharedReportResultFromResponse(404, errorBody("not_found"))).toEqual(
      { status: SHARED_REPORT_STATUS.NOT_FOUND },
    );
    expect(sharedReportResultFromResponse(429, null)).toEqual({
      status: SHARED_REPORT_STATUS.UNAVAILABLE,
    });
    expect(sharedReportResultFromResponse(200, { data: {} })).toEqual({
      status: SHARED_REPORT_STATUS.UNAVAILABLE,
    });
  });
});

describe("isPlausibleShareToken", () => {
  it("accepts urlsafe tokens and rejects anything else", () => {
    expect(isPlausibleShareToken("aB3_-".repeat(9))).toBe(true);
    expect(isPlausibleShareToken("short")).toBe(false);
    expect(isPlausibleShareToken("../../etc/passwd-0000000")).toBe(false);
    expect(isPlausibleShareToken("a".repeat(129))).toBe(false);
  });
});
