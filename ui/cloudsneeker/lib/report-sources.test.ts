import { describe, expect, it } from "vitest";

import { COMPLIANCE_PROVIDER_TYPES } from "@/cloudsneeker/compliance/single-scan-scope";
import { REPORT_TYPE_ID } from "@/cloudsneeker/types/reports";

import {
  applicableProviderIds,
  applicableProviderTypes,
  frameworkProviderType,
  groupReportSources,
  matchesSourceQuery,
  providerTypeMap,
  REPORT_SOURCE_SCOPE,
  sourceScopeNote,
  sourcesForReport,
} from "./report-sources";

const sources = [
  { id: "aws", label: "Prod", providerType: "aws" },
  { id: "m365", label: "Tenant", providerType: "m365" },
  { id: "k8s", label: "Cluster", providerType: "kubernetes" },
  { id: "repo", label: "github.com/acme/api", providerType: "iac" },
  { id: "img", label: "acme/web:1.2", providerType: "image" },
];

const ids = (list: { id: string }[]) => list.map((source) => source.id);

describe("report sources", () => {
  it("has a rule for every report type", () => {
    expect(Object.keys(REPORT_SOURCE_SCOPE).sort()).toEqual(
      Object.values(REPORT_TYPE_ID).sort(),
    );
  });

  it.each([
    ["cloud_posture", ["aws", "m365", "k8s"]],
    ["compliance", ["aws", "m365", "k8s"]],
    ["cloud_assessment", ["aws", "m365", "k8s"]],
    ["governance_assessment", ["aws", "m365", "k8s"]],
    ["governance", ["aws", "k8s"]],
    ["sca", ["k8s", "repo", "img"]],
    ["licenses", ["k8s", "repo", "img"]],
    ["sbom", ["k8s", "repo", "img"]],
    ["remediation", ["k8s", "repo", "img"]],
    ["appsec_assessment", ["k8s", "repo", "img"]],
    ["sast", ["repo"]],
    ["iac", ["repo"]],
    ["container", ["k8s", "img"]],
    ["executive", ["aws", "m365", "k8s", "repo", "img"]],
    ["exceptions", ["aws", "m365", "k8s", "repo", "img"]],
    ["secrets", ["aws", "m365", "k8s", "repo", "img"]],
    ["security_assessment", ["aws", "m365", "k8s", "repo", "img"]],
  ])("%s offers %j", (reportType, expected) => {
    expect(ids(sourcesForReport(reportType, sources))).toEqual(expected);
  });

  it("uses the posture provider list for cloud reports", () => {
    expect(applicableProviderTypes("cloud_posture")).toEqual(
      COMPLIANCE_PROVIDER_TYPES,
    );
    expect(applicableProviderTypes("executive")).toBeNull();
    expect(applicableProviderTypes("not-a-report")).toBeNull();
  });

  it("narrows compliance to the framework's provider", () => {
    expect(frameworkProviderType("cis_2.0_aws")).toBe("aws");
    expect(frameworkProviderType("cis_1.0_googleworkspace")).toBe(
      "googleworkspace",
    );
    expect(frameworkProviderType("custom_framework")).toBeNull();
    expect(frameworkProviderType("")).toBeNull();
    expect(ids(sourcesForReport("compliance", sources, "cis_2.0_aws"))).toEqual(
      ["aws"],
    );
    expect(sourceScopeNote("compliance", "cis_2.0_aws")).toMatch(
      /this framework covers/,
    );
    // The framework only narrows the compliance report.
    expect(ids(sourcesForReport("executive", sources, "cis_2.0_aws"))).toEqual(
      ids(sources),
    );
  });

  it("says which kinds are shown", () => {
    expect(sourceScopeNote("cloud_posture")).toBe(
      "Showing cloud and SaaS accounts only.",
    );
    expect(sourceScopeNote("iac")).toMatch(/repositories and code only/);
    expect(sourceScopeNote("container")).toMatch(/images and clusters only/);
    expect(sourceScopeNote("executive")).toBeNull();
  });

  it("groups cloud and SaaS, or repositories, images, and clusters", () => {
    expect(
      groupReportSources("cloud_posture", sources).map((group) => [
        group.label,
        ids(group.sources),
      ]),
    ).toEqual([
      ["Cloud accounts", ["k8s", "aws"]],
      ["SaaS accounts", ["m365"]],
    ]);
    expect(
      groupReportSources("sca", sources).map((group) => [
        group.label,
        ids(group.sources),
      ]),
    ).toEqual([
      ["Repositories and code", ["repo"]],
      ["Container images", ["img"]],
      ["Kubernetes clusters", ["k8s"]],
    ]);
  });

  it("searches labels and provider types", () => {
    expect(matchesSourceQuery(sources[3], "ACME")).toBe(true);
    expect(matchesSourceQuery(sources[0], "aws")).toBe(true);
    expect(matchesSourceQuery(sources[0], "azure")).toBe(false);
    expect(matchesSourceQuery(sources[0], "  ")).toBe(true);
  });

  it("drops selected sources of another type and keeps unknown ids", () => {
    const types = providerTypeMap(sources);
    expect(
      applicableProviderIds("cloud_posture", ["aws", "repo", "gone"], types),
    ).toEqual(["aws", "gone"]);
    expect(applicableProviderIds("iac", ["aws", "repo"], types)).toEqual([
      "repo",
    ]);
    expect(
      applicableProviderIds("compliance", ["aws", "m365"], types, "cis_aws"),
    ).toEqual(["aws"]);
    expect(providerTypeMap([{ id: "x" }])).toEqual({});
  });
});
