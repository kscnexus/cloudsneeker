import { describe, expect, it } from "vitest";

import {
  alertConditionAreas,
  newAlertHref,
  requestedNewAlertArea,
} from "./alert-areas";

describe("alertConditionAreas", () => {
  it("defaults to cloud and application security", () => {
    expect(
      alertConditionAreas({ op: "any", filter: { severity: ["high"] } }),
    ).toEqual(["cloud", "application_security"]);
  });

  it("collects nested areas in a stable order", () => {
    expect(
      alertConditionAreas({
        op: "or",
        children: [
          { op: "any", filter: { area: ["governance"] } },
          { op: "not", child: { op: "any", filter: { area: "cloud" } } },
        ],
      }),
    ).toEqual(["cloud", "governance"]);
  });

  it("ignores unknown values", () => {
    expect(alertConditionAreas({ op: "any", filter: { area: ["x"] } })).toEqual(
      ["cloud", "application_security"],
    );
  });
});

describe("new alert links", () => {
  it("round-trips the area", () => {
    const href = newAlertHref("governance");
    expect(href).toBe("/alerts?new=1&area=governance");
    const params = Object.fromEntries(new URL(href, "http://x").searchParams);
    expect(requestedNewAlertArea(params)).toBe("governance");
  });

  it("returns null without the flag and cloud for a bad area", () => {
    expect(requestedNewAlertArea({})).toBeNull();
    expect(requestedNewAlertArea({ new: "1", area: "nope" })).toBe("cloud");
  });
});
