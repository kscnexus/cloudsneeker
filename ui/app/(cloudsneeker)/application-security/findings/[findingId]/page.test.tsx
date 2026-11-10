import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("Application Security finding page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");
  const detail = readFileSync(
    path.join(
      currentDir,
      "../../../../../cloudsneeker/components/app-security-finding-detail.tsx",
    ),
    "utf8",
  );

  it("loads one finding by uid, closed ones included", () => {
    expect(source).toContain('"filter[uid]": uid');
    expect(source).toContain('"filter[status]": "all"');
    expect(source).toContain("<AppSecurityFindingDetail");
    expect(source).toContain("This finding is not in the latest scans");
  });

  it("answers what, where, why, fix, verify and status", () => {
    for (const title of [
      "Summary",
      "Where it is",
      "Why it matters",
      "What is wrong",
      "How to fix",
      "How to verify the fix",
      "Assignment and status",
    ]) {
      expect(detail).toContain(`title="${title}"`);
    }
  });

  it("never names the engines", () => {
    for (const text of [source, detail]) {
      expect(text).not.toMatch(
        /\b(Trivy|Custodian|OpenGrep|Semgrep|Prowler)\b/,
      );
    }
  });
});
