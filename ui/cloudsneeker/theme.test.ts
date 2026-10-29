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

const opsCss = readFileSync(
  path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "styles",
    "ops-surfaces.css",
  ),
  "utf8",
);

const TABLE_SCOPE = [
  "[data-cloudsneeker-surface] ~ [data-table-scroll-container]",
  "[data-cloudsneeker-surface] ~ * [data-table-scroll-container]",
];

const DIALOG_SCOPE = [
  'body:has([data-cloudsneeker-surface]) [data-slot="dialog-content"]',
  '[data-slot="dialog-content"]:has(#alert-name)',
  '[data-slot="dialog-content"]:has(#scan-configuration-name)',
];

describe("theme.css alerts and scan profiles surfaces", () => {
  it("imports the scoped stylesheet before any other rule", () => {
    const importAt = css.indexOf('@import "./styles/ops-surfaces.css";');

    expect(importAt).toBeGreaterThan(-1);
    expect(importAt).toBeLessThan(css.indexOf(":root"));
  });

  it("scopes the table restyle to pages that carry the surface marker", () => {
    for (const selector of TABLE_SCOPE) {
      expect(opsCss).toContain(selector);
    }
    expect(opsCss).toMatch(/thead\s+th \{[^}]*border-radius: 0;/);
    expect(opsCss).toMatch(/td::after \{[^}]*display: none;/);
    expect(opsCss).toContain('button[aria-haspopup="menu"]');
    expect(opsCss).toContain('> div:has([aria-label="Go to first page"])');
  });

  it("never restyles every data table in the app", () => {
    expect(opsCss).not.toMatch(/^\[data-table-scroll-container\]/m);
    expect(opsCss).not.toMatch(/^table/m);
  });

  it("scopes dialogs by page marker or by the form field ids", () => {
    for (const selector of DIALOG_SCOPE) {
      expect(opsCss).toContain(selector);
    }
    expect(opsCss).toContain('[data-slot="dialog-header"]');
    expect(opsCss).toContain('[data-slot="field-label"]');
    expect(opsCss).not.toMatch(/^\[data-slot="dialog-content"\] \{/m);
  });

  it("keeps keyboard focus visible on tables and dialogs", () => {
    expect(opsCss).toMatch(
      /:is\(a, button, \[role="combobox"\]\):focus-visible \{[^}]*outline: 2px solid/,
    );
    expect(opsCss).toMatch(/\[data-slot="dialog-close"\]\):focus-visible/);
  });

  it("restyles both empty states", () => {
    expect(opsCss).toContain(
      '[data-cloudsneeker-surface="alerts"] ~ * > [data-slot="card"]',
    );
    expect(opsCss).toContain(
      '[data-cloudsneeker-surface="scan-profiles"] ~ [data-slot="card"]',
    );
  });

  it("fits dialogs and wraps button rows at phone width", () => {
    const start = opsCss.indexOf("@media (max-width: 39.99rem)");
    expect(start).toBeGreaterThan(-1);
    const block = opsCss.slice(start);

    expect(block).toContain("max-height: calc(100dvh - 2rem);");
    expect(block).toMatch(
      /div:has\(> \[data-slot="button"\]\) \{[^}]*flex-wrap: wrap;/,
    );
  });

  it("uses theme tokens instead of fixed colors for surfaces and text", () => {
    expect(opsCss).not.toMatch(/#[0-9a-f]{3,6}\b/i);
  });
});
