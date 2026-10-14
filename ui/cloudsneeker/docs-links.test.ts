import { describe, expect, it, vi } from "vitest";

import type * as BrandModule from "./brand";
import {
  isDocumentationHref,
  shouldRenderDocumentationHref,
  showDocumentationLinks,
} from "./docs-links";

describe("docs-links", () => {
  it("ships with documentation hyperlinks disabled", async () => {
    const actual = await vi.importActual<typeof BrandModule>("./brand");
    expect(actual.BRAND.showDocumentationLinks).toBe(false);
  });

  it("detects product documentation URLs", async () => {
    const actual = await vi.importActual<typeof BrandModule>("./brand");
    expect(isDocumentationHref(actual.BRAND.docsUrl)).toBe(true);
    expect(
      isDocumentationHref(`${actual.BRAND.docsUrl}/user-guide/alerts`),
    ).toBe(true);
    expect(isDocumentationHref("https://docs.prowler.com/projects/foo")).toBe(
      true,
    );
  });

  it("does not treat in-app or support URLs as documentation", async () => {
    const actual = await vi.importActual<typeof BrandModule>("./brand");
    expect(isDocumentationHref("/profile")).toBe(false);
    expect(isDocumentationHref("/alerts")).toBe(false);
    expect(isDocumentationHref(actual.BRAND.supportUrl)).toBe(false);
    expect(isDocumentationHref(actual.BRAND.websiteUrl)).toBe(false);
  });

  it("honors the vitest brand mock so upstream Learn more assertions still pass", () => {
    expect(showDocumentationLinks()).toBe(true);
    expect(shouldRenderDocumentationHref("https://docs.prowler.com/x")).toBe(
      true,
    );
    expect(shouldRenderDocumentationHref("/profile")).toBe(true);
  });
});
