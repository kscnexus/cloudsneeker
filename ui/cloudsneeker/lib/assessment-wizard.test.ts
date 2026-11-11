import { describe, expect, it } from "vitest";

import {
  ASSESSMENT_PERIOD,
  ASSESSMENT_SECTION,
  assessmentSummary,
  buildAssessmentPayload,
  defaultSections,
  initialWizardState,
  isAssessmentType,
  qualityLabel,
  scopeLabel,
  scopeSources,
  sectionsFor,
  sourcesFor,
  stepError,
  WIZARD_STEP,
  withReportType,
} from "./assessment-wizard";

const providers = [
  { id: "a", attributes: { provider: "aws", alias: "prod", uid: "111" } },
  {
    id: "b",
    attributes: { provider: "iac", alias: "", uid: "github.com/acme/api" },
  },
  { id: "c", attributes: { provider: "kubernetes", uid: "cluster-1" } },
];

describe("assessment wizard", () => {
  it("recognizes assessment report types only", () => {
    expect(isAssessmentType("security_assessment")).toBe(true);
    expect(isAssessmentType("executive")).toBe(false);
  });

  it("offers the sources relevant to each report type", () => {
    const sources = scopeSources(providers);
    expect(sources[1].label).toBe("github.com/acme/api");
    expect(sourcesFor("appsec_assessment", sources).map((s) => s.id)).toEqual([
      "b",
      "c",
    ]);
    expect(sourcesFor("cloud_assessment", sources).map((s) => s.id)).toEqual([
      "a",
      "c",
    ]);
    expect(
      sourcesFor("governance_assessment", sources).map((s) => s.id),
    ).toEqual(["a"]);
    expect(sourcesFor("security_assessment", sources)).toHaveLength(3);
  });

  it("keeps compliance out of application and cloud reports", () => {
    expect(sectionsFor("appsec_assessment")).not.toContain(
      ASSESSMENT_SECTION.COMPLIANCE,
    );
    expect(sectionsFor("governance_assessment")).toContain(
      ASSESSMENT_SECTION.COMPLIANCE,
    );
    expect(defaultSections("security_assessment")).not.toContain(
      ASSESSMENT_SECTION.AI_INSIGHTS,
    );
  });

  it("resets type-specific choices when the type changes", () => {
    const state = {
      ...initialWizardState("governance_assessment"),
      providerIds: ["a"],
      frameworks: ["cis_2.0_aws"],
    };
    const next = withReportType(state, "appsec_assessment");
    expect(next.providerIds).toEqual([]);
    expect(next.frameworks).toEqual([]);
    expect(next.sections).toEqual(defaultSections("appsec_assessment"));
  });

  it("validates the custom period and formats", () => {
    const state = { ...initialWizardState(), period: ASSESSMENT_PERIOD.CUSTOM };
    expect(stepError(WIZARD_STEP.PERIOD, state)).toMatch(/Pick a start/);
    expect(
      stepError(WIZARD_STEP.PERIOD, {
        ...state,
        dateFrom: "2026-02-01",
        dateTo: "2026-01-01",
      }),
    ).toMatch(/before the end/);
    expect(
      stepError(WIZARD_STEP.PERIOD, { ...state, dateTo: "2026-01-01" }),
    ).toBeNull();
    expect(stepError(WIZARD_STEP.GENERATE, { ...state, formats: [] })).toMatch(
      /file format/,
    );
    expect(stepError(WIZARD_STEP.SCOPE, { ...state, staleDays: 0 })).toMatch(
      /between 1 and 90/,
    );
  });

  it("builds the API payload with only accepted keys", () => {
    const payload = buildAssessmentPayload({
      ...initialWizardState("appsec_assessment"),
      providerIds: ["b"],
      frameworks: ["ignored"],
      sections: [ASSESSMENT_SECTION.COMPLIANCE, ASSESSMENT_SECTION.ROADMAP],
    });
    expect(payload).toEqual({
      reportType: "appsec_assessment",
      params: {
        provider_ids: ["b"],
        period: "30d",
        sections: ["roadmap"],
        stale_days: 7,
      },
      formats: ["pdf", "csv"],
    });
    const custom = buildAssessmentPayload({
      ...initialWizardState("governance_assessment"),
      period: ASSESSMENT_PERIOD.CUSTOM,
      dateFrom: "2026-01-01",
      frameworks: ["cis_2.0_aws"],
    });
    expect(custom.params.date_from).toBe("2026-01-01");
    expect(custom.params.date_to).toBeUndefined();
    expect(custom.params.frameworks).toEqual(["cis_2.0_aws"]);
  });

  it("reads the stored run summary", () => {
    const summary = assessmentSummary({
      summary: {
        period: "Last 30 days",
        scope: ["prod", "staging", "api"],
        engine_version: "2.0",
        warnings: ["1 source(s) were last assessed more than 7 days ago"],
        quality: {
          status: "warn",
          distributable: true,
          summary: "16 checks",
          failed: [],
        },
        grade: "B",
        score: 84.2,
        pages: 23,
      },
    });
    expect(summary.version).toBe("2.0");
    expect(scopeLabel(summary, 0)).toBe("prod, staging +1");
    expect(qualityLabel(summary)).toBe("Distributable, with warnings");
    const empty = assessmentSummary({ summary: undefined });
    expect(empty.distributable).toBeNull();
    expect(qualityLabel(empty)).toBe("Not checked");
    expect(scopeLabel(empty, 0)).toBe("All visible sources");
    expect(
      qualityLabel(
        assessmentSummary({ summary: { quality: { distributable: false } } }),
      ),
    ).toBe("Not distributable");
  });
});
