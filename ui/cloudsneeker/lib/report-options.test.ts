import { describe, expect, it } from "vitest";

import { buildReportCatalog } from "@/cloudsneeker/lib/report-catalog";
import {
  frameworkOptions,
  latestScanPerProvider,
  providerOptions,
} from "@/cloudsneeker/lib/report-options";
import {
  formatBytes,
  frameworkLabel,
  humanizeKey,
  isReportRunActive,
  severityChartData,
} from "@/cloudsneeker/lib/report-view";
import type { ReportTypeResource } from "@/cloudsneeker/types/reports";

describe("report options", () => {
  it("labels providers by type and alias", () => {
    expect(
      providerOptions([
        { id: "p1", attributes: { provider: "aws", alias: "Prod", uid: "123" } },
        { id: "p2", attributes: { provider: "iac", alias: null, uid: "repo" } },
      ]),
    ).toEqual([
      { id: "p1", label: "aws · Prod" },
      { id: "p2", label: "iac · repo" },
    ]);
  });

  it("keeps the newest scan per provider", () => {
    const scan = (id: string, provider: string) => ({
      id,
      relationships: { provider: { data: { id: provider } } },
    });
    expect(
      latestScanPerProvider(
        [scan("s1", "a"), scan("s2", "a"), scan("s3", "b"), scan("s4", "c")],
        2,
      ),
    ).toEqual(["s1", "s3"]);
  });

  it("deduplicates frameworks and hides the upstream product name", () => {
    expect(
      frameworkOptions([
        [
          { id: "cis_2.0_aws", attributes: { framework: "CIS", version: "2.0" } },
          {
            id: "prowler_threatscore_aws",
            attributes: { framework: "ProwlerThreatScore", version: "1.0" },
          },
        ],
        [{ id: "cis_2.0_aws", attributes: { framework: "CIS", version: "2.0" } }],
      ]),
    ).toEqual([
      { id: "cis_2.0_aws", label: "CIS 2.0 · AWS" },
      { id: "prowler_threatscore_aws", label: "ThreatScore 1.0 · AWS" },
    ]);
  });
});

describe("report catalog", () => {
  it("applies product copy and flags the framework requirement", () => {
    const types: ReportTypeResource[] = [
      {
        type: "cloudsneeker-report-types",
        id: "compliance",
        attributes: {
          name: "Compliance",
          description: "api copy",
          audience: "engineering",
          category: "compliance",
          formats: ["pdf"],
          parameters: { required: ["compliance_id"], optional: [] },
        },
      },
      {
        type: "cloudsneeker-report-types",
        id: "future_type",
        attributes: {
          name: "Future",
          description: "Future description",
          audience: "management",
          category: "overview",
          formats: ["pdf"],
          parameters: { required: [], optional: [] },
        },
      },
    ];
    const catalog = buildReportCatalog(types);
    expect(catalog[0]).toMatchObject({ id: "compliance", requiresFramework: true });
    expect(catalog[0]?.description).not.toBe("api copy");
    expect(catalog[1]).toMatchObject({
      title: "Future",
      description: "Future description",
      requiresFramework: false,
    });
    for (const entry of catalog) {
      expect(`${entry.title} ${entry.description}`).not.toMatch(
        /prowler|trivy|custodian|opengrep|semgrep/i,
      );
    }
  });
});

describe("report view helpers", () => {
  it("formats keys, sizes and frameworks", () => {
    expect(humanizeKey("failed_findings")).toBe("Failed findings");
    expect(humanizeKey("cve_count")).toBe("CVE count");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(0)).toBe("");
    expect(frameworkLabel("cis_2.0_aws")).toBe("CIS 2.0 AWS");
    expect(frameworkLabel("prowler_threatscore_aws")).toBe("Threatscore AWS");
  });

  it("knows which runs are still in progress", () => {
    expect(isReportRunActive("pending")).toBe(true);
    expect(isReportRunActive("running")).toBe(true);
    expect(isReportRunActive("completed")).toBe(false);
  });

  it("orders severity chart rows most severe first", () => {
    expect(severityChartData({ low: 2, critical: 1 })).toEqual([
      { name: "Critical", value: 1 },
      { name: "High", value: 0 },
      { name: "Medium", value: 0 },
      { name: "Low", value: 2 },
      { name: "Informational", value: 0 },
    ]);
  });
});
