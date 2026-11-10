import { describe, expect, it } from "vitest";

import {
  daysUntil,
  defaultRiskAcceptance,
  isoDateAfter,
  riskAcceptanceProblem,
} from "./risk-acceptance";

const TODAY = new Date("2026-11-10T22:30:00Z");

describe("risk acceptance helpers", () => {
  it("computes UTC dates", () => {
    expect(isoDateAfter(1, TODAY)).toBe("2026-11-11");
    expect(isoDateAfter(90, TODAY)).toBe("2027-02-08");
    expect(defaultRiskAcceptance(TODAY)).toEqual({
      risk_reason: "",
      risk_expires_on: "2027-02-08",
    });
  });

  it("explains what is missing", () => {
    const valid = { risk_reason: "WAF rule", risk_expires_on: "2026-12-01" };
    expect(riskAcceptanceProblem(valid, TODAY)).toBeNull();
    expect(
      riskAcceptanceProblem({ ...valid, risk_reason: "  " }, TODAY),
    ).toMatch(/reason/);
    expect(
      riskAcceptanceProblem({ ...valid, risk_expires_on: "" }, TODAY),
    ).toMatch(/expiry date/);
    expect(
      riskAcceptanceProblem({ ...valid, risk_expires_on: "2026-11-10" }, TODAY),
    ).toMatch(/after today/);
    expect(
      riskAcceptanceProblem({ ...valid, risk_expires_on: "2028-01-01" }, TODAY),
    ).toMatch(/at most 365 days/);
  });

  it("counts days until expiry", () => {
    expect(daysUntil("2026-11-20", TODAY)).toBe(10);
    expect(daysUntil("2026-11-09", TODAY)).toBe(-1);
  });
});
