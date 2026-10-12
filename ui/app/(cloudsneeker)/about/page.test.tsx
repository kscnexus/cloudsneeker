import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

describe("About page", () => {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const source = readFileSync(path.join(currentDir, "page.tsx"), "utf8");
  const layoutSource = readFileSync(
    path.join(currentDir, "..", "layout.tsx"),
    "utf8",
  );

  it("reuses the signed-in application shell", () => {
    expect(layoutSource).toContain('from "../(prowler)/layout"');
    expect(layoutSource).toMatch(/export \{ default, metadata, viewport \}/);
  });

  it("titles the page with the brand name and loads the brand from the API", () => {
    expect(source).toContain("title={`About ${BRAND.name}`}");
    expect(source).toContain('from "@/cloudsneeker/actions/brand"');
    expect(source).toContain(
      "<AboutCard attributes={brand?.data.attributes} />",
    );
  });

  it("does not hard-code the upstream product name", () => {
    expect(source).not.toMatch(/prowler/i);
  });
});
