import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Triage page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

  it("lists triaged findings filtered by status", () => {
    expect(source).toContain("listFindingTriages");
    expect(source).toContain("parseTriageStatus");
    expect(source).toContain("triageListSearchParams");
    expect(source).toContain("<FindingTriageStatusFilter");
    expect(source).toContain("<FindingTriageTable");
  });

  it("shows a load error instead of an empty list when the request fails", () => {
    expect(source).toContain("isListResponse(response)");
    expect(source).toContain("Triage could not be loaded");
  });

  it("uses the shared page components", () => {
    expect(source).toContain("<PageHeader");
    expect(source).toContain("<SectionCard");
    expect(source).toContain("<EmptyState");
  });

  it("never names the upstream product", () => {
    expect(source).not.toMatch(/\bProwler\b/);
  });
});
