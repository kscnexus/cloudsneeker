import { describe, expect, it } from "vitest";

import { BRAND } from "./brand";
import { brandSystemPrompt } from "./lighthouse-prompt";

const TEMPLATE = `
## Introduction

You are powered by Prowler. Data comes from Prowler Local Server and Prowler Hub.

## Sources and Domain Knowledge

- Prowler website: https://prowler.com/
- Prowler Cloud: https://cloud.prowler.com/
`;

describe("brandSystemPrompt", () => {
  it("replaces every upstream mention with the product name", () => {
    const prompt = brandSystemPrompt(TEMPLATE);

    expect(prompt).not.toMatch(/prowler/i);
    expect(prompt).toContain(`You are powered by ${BRAND.name}.`);
    expect(prompt).toContain(
      `Data comes from ${BRAND.name} and ${BRAND.name}.`,
    );
  });

  it("replaces the sources block with product-owned links", () => {
    const prompt = brandSystemPrompt(TEMPLATE);

    expect(prompt).toContain("## Sources and Domain Knowledge");
    expect(prompt).toContain(BRAND.docsUrl);
    expect(prompt).toContain(BRAND.supportUrl);
  });

  it("renames the assistant", () => {
    const prompt = brandSystemPrompt(
      "Ask Lighthouse AI. Lighthouse can help.",
    );

    expect(prompt).toContain(`Ask ${BRAND.assistantName}.`);
    expect(prompt).toContain(`${BRAND.assistantName} can help.`);
    expect(prompt).not.toMatch(/Lighthouse/);
  });

  it("appends sources when the template has none", () => {
    const prompt = brandSystemPrompt("Hello from Prowler.");

    expect(prompt.startsWith(`Hello from ${BRAND.name}.`)).toBe(true);
    expect(prompt).toContain(BRAND.websiteUrl);
  });
});
