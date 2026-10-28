import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Trivy page workspace", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

  it("lists targets and recent runs with findings links", () => {
    expect(source).toContain("listTrivyTargets");
    expect(source).toContain("listTrivyRuns");
    expect(source).toContain("TrivyTargetList");
    expect(source).toContain("findingsHrefForScan");
    expect(source).toContain("New target");
  });
});
