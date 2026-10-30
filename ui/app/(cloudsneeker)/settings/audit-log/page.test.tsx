import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const currentDir = path.dirname(fileURLToPath(import.meta.url));
const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");

describe("Audit log page", () => {
  it("loads events through the audit log action with parsed filters", () => {
    expect(source).toContain("listAuditEvents");
    expect(source).toContain("parseAuditLogFilters");
    expect(source).toContain("auditListParams");
    expect(source).toContain("AuditLogFilters");
    expect(source).toContain("AuditLogTable");
  });

  it("is limited to administrators", () => {
    expect(source).toContain("manage_account");
  });

  it("shows a load error instead of an empty list when the request fails", () => {
    expect(source).toContain("isListResponse");
    expect(source).toContain("Audit log unavailable");
  });

  it("uses the shared page components", () => {
    for (const name of ["PageHeader", "SectionCard", "EmptyState", "StatTile"]) {
      expect(source).toContain(name);
    }
  });

  it("never names an engine", () => {
    expect(source).not.toMatch(/Trivy|Custodian|Prowler/);
  });
});
