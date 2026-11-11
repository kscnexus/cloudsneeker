import { describe, expect, it } from "vitest";

import {
  TRIVY_RUN_STATUS,
  TRIVY_RUN_TRIGGER,
  type TrivyRunResource,
} from "@/cloudsneeker/types/trivy";

import {
  getScanHistoryPage,
  getScanHistoryView,
  groupRunsByTarget,
  responsePages,
  SCAN_HISTORY_VIEW,
  scanHistoryHref,
} from "./app-security-scan-history";

const run = (
  id: string,
  targetId: string,
  insertedAt: string,
  targetName = `name-${targetId}`,
): TrivyRunResource => ({
  id,
  type: "cloudsneeker-trivy-runs",
  attributes: {
    target_id: targetId,
    target_name: targetName,
    target_mode: "repo",
    provider_id: "p1",
    status: TRIVY_RUN_STATUS.COMPLETED,
    trigger: TRIVY_RUN_TRIGGER.MANUAL,
    inserted_at: insertedAt,
  },
});

describe("groupRunsByTarget", () => {
  it("groups runs per target, newest run and newest group first", () => {
    const groups = groupRunsByTarget([
      run("a1", "a", "2026-11-01T10:00:00Z"),
      run("b1", "b", "2026-11-09T10:00:00Z"),
      run("a2", "a", "2026-11-05T10:00:00Z"),
      run("b2", "b", "2026-11-02T10:00:00Z"),
    ]);

    expect(groups.map((group) => group.targetId)).toEqual(["b", "a"]);
    expect(groups[0].runs.map((item) => item.id)).toEqual(["b1", "b2"]);
    expect(groups[1].runs.map((item) => item.id)).toEqual(["a2", "a1"]);
    expect(groups[0]).toMatchObject({
      targetName: "name-b",
      targetMode: "repo",
    });
  });

  it("falls back to the target id when the name is missing", () => {
    const [group] = groupRunsByTarget([
      run("a1", "a", "2026-11-01T10:00:00Z", ""),
    ]);

    expect(group.targetName).toBe("a");
  });

  it("returns no groups for no runs", () => {
    expect(groupRunsByTarget([])).toEqual([]);
  });
});

describe("scan history view and paging", () => {
  it("reads the view from the query", () => {
    expect(getScanHistoryView("archived")).toBe(SCAN_HISTORY_VIEW.ARCHIVED);
    expect(getScanHistoryView(["archived"])).toBe(SCAN_HISTORY_VIEW.ARCHIVED);
    expect(getScanHistoryView("other")).toBe(SCAN_HISTORY_VIEW.CURRENT);
    expect(getScanHistoryView(undefined)).toBe(SCAN_HISTORY_VIEW.CURRENT);
  });

  it("reads a positive page number", () => {
    expect(getScanHistoryPage("3")).toBe(3);
    expect(getScanHistoryPage("0")).toBe(1);
    expect(getScanHistoryPage("x")).toBe(1);
    expect(getScanHistoryPage(undefined)).toBe(1);
  });

  it("reads the page count of a list response", () => {
    expect(responsePages({ meta: { pagination: { pages: 4 } } })).toBe(4);
    expect(responsePages({ meta: { pagination: { pages: 0 } } })).toBe(1);
    expect(responsePages({ data: [] })).toBe(1);
    expect(responsePages(null)).toBe(1);
  });

  it("links to the Scans tab views", () => {
    expect(scanHistoryHref(SCAN_HISTORY_VIEW.CURRENT)).toBe(
      "/application-security/scans",
    );
    expect(scanHistoryHref(SCAN_HISTORY_VIEW.ARCHIVED)).toBe(
      "/application-security/scans?history=archived",
    );
    expect(scanHistoryHref(SCAN_HISTORY_VIEW.ARCHIVED, 2)).toBe(
      "/application-security/scans?history=archived&page=2",
    );
  });
});
