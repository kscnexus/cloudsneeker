import { describe, expect, it } from "vitest";

import {
  TRIVY_RUN_STATUS,
  TRIVY_RUN_TRIGGER,
  type TrivyRunResource,
} from "@/cloudsneeker/types/trivy";

import {
  applicationFindingsHref,
  archivedScansHref,
  errorSnippet,
  formatDuration,
  isApplicationId,
  parseScanFilters,
  runDurationMs,
  runFindingCount,
  SCAN_TYPE_LABEL,
  scanRunsQuery,
  scansHref,
  scanTriggerLabel,
  scanTypeLabel,
} from "./app-security-scans";

const APP_ID = "0b6c1e7a-1f2d-4c3b-9a8e-5d4c3b2a1f00";

const run = (
  attributes: Partial<TrivyRunResource["attributes"]> = {},
): TrivyRunResource => ({
  id: "run-1",
  type: "trivy-runs",
  attributes: {
    target_id: "target-1",
    provider_id: APP_ID,
    status: TRIVY_RUN_STATUS.COMPLETED,
    trigger: TRIVY_RUN_TRIGGER.MANUAL,
    ...attributes,
  },
});

describe("scan type labels", () => {
  it("uses short labels for every mode", () => {
    expect(SCAN_TYPE_LABEL.repo).toBe("Code repository");
    expect(SCAN_TYPE_LABEL.fs).toBe("Filesystem");
    expect(SCAN_TYPE_LABEL.image).toBe("Container image");
    expect(SCAN_TYPE_LABEL.iac).toBe("Infrastructure as code");
    expect(SCAN_TYPE_LABEL.sbom).toBe("SBOM");
    expect(SCAN_TYPE_LABEL.k8s).toBe("Kubernetes");
    expect(SCAN_TYPE_LABEL.sast).toBe("Static analysis");
  });

  it("falls back to the raw value or a dash", () => {
    expect(scanTypeLabel("other")).toBe("other");
    expect(scanTypeLabel(undefined)).toBe("—");
    expect(scanTriggerLabel("scheduled")).toBe("Scheduled");
    expect(scanTriggerLabel("")).toBe("—");
  });
});

describe("parseScanFilters", () => {
  it("keeps known values and drops the rest", () => {
    expect(
      parseScanFilters({
        status: "failed",
        type: "sast",
        trigger: "scheduled",
        app: APP_ID,
        page: "3",
      }),
    ).toEqual({
      status: "failed",
      mode: "sast",
      trigger: "scheduled",
      application: APP_ID,
      page: 3,
    });
    expect(
      parseScanFilters({
        status: "bogus",
        type: "x",
        trigger: "cron",
        app: "not-a-uuid",
        page: "-2",
      }),
    ).toEqual({
      status: undefined,
      mode: undefined,
      trigger: undefined,
      application: undefined,
      page: 1,
    });
  });

  it("reads the first of repeated values", () => {
    expect(parseScanFilters({ status: ["running", "failed"] }).status).toBe(
      "running",
    );
  });

  it("validates application ids as UUIDs", () => {
    expect(isApplicationId(APP_ID)).toBe(true);
    expect(isApplicationId("abc")).toBe(false);
    expect(isApplicationId(undefined)).toBe(false);
  });
});

describe("scanRunsQuery", () => {
  it("asks for current scans newest first with the filters", () => {
    expect(
      scanRunsQuery({
        status: "completed",
        mode: "repo",
        trigger: "manual",
        application: APP_ID,
        page: 2,
      }),
    ).toEqual({
      "filter[archived]": "false",
      sort: "-inserted_at",
      "page[size]": "25",
      "page[number]": "2",
      "filter[status]": "completed",
      "filter[mode]": "repo",
      "filter[trigger]": "manual",
      "filter[provider]": APP_ID,
    });
  });

  it("omits empty filters and honours the page size", () => {
    expect(scanRunsQuery({ page: 1 }, 1)).toEqual({
      "filter[archived]": "false",
      sort: "-inserted_at",
      "page[size]": "1",
      "page[number]": "1",
    });
  });
});

describe("scansHref", () => {
  it("is the bare route without filters", () => {
    expect(scansHref()).toBe("/application-security/scans");
  });

  it("merges overrides and resets the page", () => {
    expect(scansHref({ status: "failed", page: 4 }, { mode: "image" })).toBe(
      "/application-security/scans?status=failed&type=image",
    );
    expect(scansHref({ status: "failed" }, { status: undefined })).toBe(
      "/application-security/scans",
    );
    expect(scansHref({ trigger: "manual" }, { page: 2 })).toBe(
      "/application-security/scans?trigger=manual&page=2",
    );
  });

  it("links archived scans and application findings", () => {
    expect(archivedScansHref()).toBe(
      "/application-security?tab=scans&history=archived",
    );
    expect(applicationFindingsHref(APP_ID, { category: "sca" })).toBe(
      `/application-security/findings?app=${APP_ID}&category=sca`,
    );
  });
});

describe("durations", () => {
  it("measures finished runs", () => {
    expect(
      runDurationMs(
        run({
          started_at: "2026-11-01T10:00:00Z",
          finished_at: "2026-11-01T10:03:05Z",
        }),
      ),
    ).toBe(185_000);
  });

  it("counts running scans up to now and skips unstarted ones", () => {
    const now = Date.parse("2026-11-01T10:00:30Z");
    expect(
      runDurationMs(
        run({
          status: TRIVY_RUN_STATUS.RUNNING,
          started_at: "2026-11-01T10:00:00Z",
        }),
        now,
      ),
    ).toBe(30_000);
    expect(runDurationMs(run({ status: TRIVY_RUN_STATUS.PENDING }))).toBe(null);
    expect(
      runDurationMs(
        run({
          status: TRIVY_RUN_STATUS.FAILED,
          started_at: "2026-11-01T10:00:00Z",
        }),
      ),
    ).toBe(null);
  });

  it("formats durations", () => {
    expect(formatDuration(null)).toBe("—");
    expect(formatDuration(500)).toBe("<1s");
    expect(formatDuration(42_000)).toBe("42s");
    expect(formatDuration(185_000)).toBe("3m 05s");
    expect(formatDuration(3_720_000)).toBe("1h 02m");
  });
});

describe("run details", () => {
  it("reads the finding count from the summary", () => {
    expect(runFindingCount(run({ summary: { finding_count: 7 } }))).toBe(7);
    expect(runFindingCount(run({ summary: { finding_count: null } }))).toBe(
      null,
    );
    expect(runFindingCount(run())).toBe(null);
  });

  it("cuts errors to their first line", () => {
    expect(errorSnippet(undefined)).toBe("");
    expect(errorSnippet("boom\nstack")).toBe("boom");
    expect(errorSnippet("x".repeat(20), 10)).toBe(`${"x".repeat(9)}…`);
  });
});
