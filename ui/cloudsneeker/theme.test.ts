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

const stylesDir = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "styles",
);
const opsCss = readFileSync(path.join(stylesDir, "ops-surfaces.css"), "utf8");
const surfacesCss = readFileSync(path.join(stylesDir, "surfaces.css"), "utf8");
const tokensCss = readFileSync(
  path.join(stylesDir, "design-tokens.css"),
  "utf8",
);
const globalsCss = readFileSync(
  path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "styles",
    "globals.css",
  ),
  "utf8",
);

describe("design tokens", () => {
  it("are imported into the Tailwind entry so they become utilities", () => {
    expect(globalsCss).toContain(
      '@import "../cloudsneeker/styles/design-tokens.css"; /* cloudsneeker-hook',
    );
    expect(globalsCss.indexOf("design-tokens.css")).toBeLessThan(
      globalsCss.indexOf("\n@plugin"),
    );
  });

  it("define the stock shadcn colors upstream components use", () => {
    for (const name of [
      "muted-foreground",
      "popover",
      "popover-foreground",
      "accent",
      "accent-foreground",
      "destructive",
      "ring",
      "card",
    ]) {
      expect(tokensCss).toContain(`--color-${name}: var(--`);
    }
  });

  it("leave the input alias undefined so dark inputs keep their fill", () => {
    expect(tokensCss).not.toMatch(/--color-input:/);
  });

  it("alias the near-miss names used in the tree", () => {
    for (const name of [
      "text-error",
      "text-info",
      "border-error-primary",
      "bg-button-secondary",
    ]) {
      expect(tokensCss).toContain(`--color-${name}:`);
    }
  });

  it("have light and dark values for every design-system variable", () => {
    const rootBlock = css.slice(css.indexOf(":root {"), css.indexOf(".dark {"));
    const darkBlock = css.slice(css.indexOf(".dark {"), css.indexOf("html {"));
    for (const name of [
      "--cs-focus-ring",
      "--cs-shadow-surface",
      "--cs-shadow-overlay",
      "--bg-info-primary",
      "--text-info-primary",
    ]) {
      expect(rootBlock).toContain(`${name}:`);
      expect(darkBlock).toContain(`${name}:`);
    }
    expect(rootBlock).toContain("--cs-radius-control:");
  });
});

describe("theme.css app-wide surfaces", () => {
  it("imports surfaces, then the page specifics, before any other rule", () => {
    const surfacesAt = css.indexOf('@import "./styles/surfaces.css";');
    const opsAt = css.indexOf('@import "./styles/ops-surfaces.css";');

    expect(surfacesAt).toBeGreaterThan(-1);
    expect(surfacesAt).toBeLessThan(opsAt);
    expect(opsAt).toBeLessThan(css.indexOf(":root"));
  });

  it("gives every shadcn table square, divided rows", () => {
    expect(surfacesCss).toMatch(
      /table\.border-spacing-y-4 > thead th \{[^}]*border-radius: 0;/,
    );
    expect(surfacesCss).toMatch(/td::after \{[^}]*display: none;/);
    expect(surfacesCss).toContain('button[aria-haspopup="menu"]');
    expect(surfacesCss).toContain(
      '[data-table-scroll-container] > div:has([aria-label="Go to first page"])',
    );
  });

  it("draws the default focus outline in the base layer", () => {
    expect(surfacesCss).toMatch(
      /@layer base \{\s*:focus-visible \{[^}]*outline: 2px solid var\(--cs-focus-ring\);/,
    );
  });

  it("styles every dialog and alert dialog the same way", () => {
    expect(surfacesCss).toContain(
      ':is([data-slot="dialog-content"], [role="alertdialog"]) {',
    );
    expect(surfacesCss).toContain('[data-slot="dialog-overlay"] {');
    expect(surfacesCss).toContain('[data-slot="dialog-title"] {');
  });

  it("recolors the tabs with product tokens", () => {
    expect(surfacesCss).toMatch(
      /\[data-slot="tabs-trigger"\]::after \{[^}]*var\(--sidebar-active-bar\)/,
    );
  });

  it("fits dialogs at phone width and respects reduced motion", () => {
    const start = surfacesCss.indexOf("@media (max-width: 39.99rem)");
    expect(start).toBeGreaterThan(-1);
    expect(surfacesCss.slice(start)).toContain(
      "max-height: calc(100dvh - 2rem);",
    );
    expect(surfacesCss).toContain("@media (prefers-reduced-motion: reduce)");
  });

  it("uses tokens instead of fixed colors", () => {
    expect(surfacesCss).not.toMatch(/#[0-9a-f]{3,6}/i);
  });
});

describe("theme.css alerts and scan profiles specifics", () => {
  it("keeps only page-specific rules", () => {
    expect(opsCss).not.toContain("[data-table-scroll-container]");
    expect(opsCss).not.toMatch(/^table/m);
    expect(opsCss).not.toContain('[data-slot="dialog-overlay"]');
  });

  it("restyles both empty states", () => {
    expect(opsCss).toContain(
      '[data-cloudsneeker-surface="alerts"] ~ * > [data-slot="card"]',
    );
    expect(opsCss).toContain(
      '[data-cloudsneeker-surface="scan-profiles"] ~ [data-slot="card"]',
    );
  });

  it("scopes dialog details by the form field ids", () => {
    expect(opsCss).toContain('[data-slot="dialog-content"]:has(#alert-name)');
    expect(opsCss).toContain(
      '[data-slot="dialog-content"]:has(#scan-configuration-name)',
    );
  });

  it("uses theme tokens instead of fixed colors for surfaces and text", () => {
    expect(opsCss).not.toMatch(/#[0-9a-f]{3,6}/i);
  });
});
