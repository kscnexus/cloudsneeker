import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Triage page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

  it("renders the shared triage view scoped to Cloud Security", () => {
    expect(source).toContain("<AreaTriageView");
    expect(source).toContain("FINDING_AREA.CLOUD");
  });

  it("never names the upstream product", () => {
    expect(source).not.toMatch(/\bProwler\b/);
  });
});
