import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const css = readFileSync(
  path.join(path.dirname(fileURLToPath(import.meta.url)), "theme.css"),
  "utf8",
);

const phoneBlock = (): string => {
  const start = css.indexOf("@media (max-width: 39.99rem)");
  expect(start).toBeGreaterThan(-1);
  return css.slice(start, css.indexOf("/* Import findings dialog", start));
};

describe("theme.css phone navbar", () => {
  it("lets the title shrink and keeps the action group at its own width", () => {
    const block = phoneBlock();

    expect(block).toContain("header.sticky.top-0 > div > div:first-child {");
    expect(block).toMatch(/div:first-child \{[^}]*min-width: 0;/);
    expect(block).toMatch(/div:last-child \{[^}]*flex: 0 0 auto;/);
  });

  it("hides only the duplicate profile link and the updates feed", () => {
    const block = phoneBlock();

    expect(block).toContain('a[aria-label="Open profile"]');
    expect(block).toContain('button[aria-label="Check for updates"]');
    expect(block).toContain('button[aria-label^="New updates available"]');
    expect(block).not.toContain('aria-label="Sign out"');
    expect(block).not.toContain('aria-label="Profile"]');
  });
});
