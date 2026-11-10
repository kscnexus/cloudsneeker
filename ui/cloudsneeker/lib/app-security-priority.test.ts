import { describe, expect, it } from "vitest";

import {
  areaFindingsPageHref,
  areaFindingsSearchParams,
  parseAreaFilters,
} from "@/cloudsneeker/lib/area-findings";
import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";

import {
  categoryImpact,
  daysUntil,
  dueText,
  validationSteps,
} from "./app-security-finding-detail";
import {
  APPLICATION_POSTURE,
  applicationPosture,
  riskPriorityText,
} from "./app-security-priority";

describe("riskPriorityText", () => {
  it("names known priorities", () => {
    expect(riskPriorityText("p0")).toBe("P0 Immediate");
    expect(riskPriorityText("p4")).toBe("P4 Low");
    expect(riskPriorityText("")).toBe("—");
    expect(riskPriorityText("p9")).toBe("—");
  });
});

describe("applicationPosture", () => {
  const summary = { total: 0, critical: 0, high: 0, urgent: 0 };
  it("ranks the worst open findings first", () => {
    expect(applicationPosture(undefined)).toBe(APPLICATION_POSTURE.NOT_SCANNED);
    expect(applicationPosture({ ...summary, total: 3, urgent: 1 })).toBe(
      APPLICATION_POSTURE.CRITICAL,
    );
    expect(applicationPosture({ ...summary, total: 2, critical: 1 })).toBe(
      APPLICATION_POSTURE.CRITICAL,
    );
    expect(applicationPosture({ ...summary, total: 2, high: 2 })).toBe(
      APPLICATION_POSTURE.AT_RISK,
    );
    expect(applicationPosture({ ...summary, total: 2 })).toBe(
      APPLICATION_POSTURE.NEEDS_REVIEW,
    );
    expect(applicationPosture(summary)).toBe(APPLICATION_POSTURE.HEALTHY);
  });
});

describe("priority, overdue and application filters", () => {
  it("round-trips through the URL and the API query", () => {
    const filters = parseAreaFilters({
      priority: "P1",
      overdue: "1",
      app: "p-1",
    });
    expect(filters).toMatchObject({
      priority: "p1",
      overdue: true,
      application: "p-1",
    });
    expect(
      areaFindingsSearchParams(FINDING_AREA.APPLICATION_SECURITY, filters),
    ).toMatchObject({
      "filter[priority__in]": "p1",
      "filter[overdue]": "true",
      "filter[application__in]": "p-1",
    });
    expect(
      areaFindingsPageHref(FINDING_AREA.APPLICATION_SECURITY, filters),
    ).toBe("/application-security/findings?priority=p1&overdue=1&app=p-1");
  });

  it("ignores unknown priorities and other areas", () => {
    expect(parseAreaFilters({ priority: "p7" }).priority).toBeUndefined();
    const params = areaFindingsSearchParams(
      FINDING_AREA.GOVERNANCE,
      parseAreaFilters({ priority: "p0", overdue: "1", app: "x" }),
    );
    expect(params["filter[priority__in]"]).toBeUndefined();
    expect(params["filter[overdue]"]).toBeUndefined();
    expect(params["filter[application__in]"]).toBeUndefined();
  });
});

describe("finding detail text", () => {
  const now = new Date("2026-11-10T00:00:00Z");

  it("counts days to the due date", () => {
    expect(daysUntil("2026-11-13T00:00:00Z", now)).toBe(3);
    expect(daysUntil(null, now)).toBeNull();
    expect(dueText("2026-11-13T00:00:00Z", false, now)).toBe("Due in 3 days");
    expect(dueText("2026-11-10T00:00:00Z", false, now)).toBe("Due today");
    expect(dueText("2026-11-08T00:00:00Z", true, now)).toBe(
      "Overdue by 2 days",
    );
    expect(dueText(undefined, false, now)).toBe("No due date");
  });

  it("verifies every fix with a rescan before closing", () => {
    const steps = validationSteps("secrets");
    expect(steps[0]).toMatch(/Revoke and rotate/);
    expect(steps.at(-1)).toMatch(/Resolved/);
    expect(validationSteps(undefined)).toHaveLength(2);
    expect(categoryImpact("sca")).toMatch(/third-party/);
    expect(categoryImpact("")).toBe("");
  });
});
