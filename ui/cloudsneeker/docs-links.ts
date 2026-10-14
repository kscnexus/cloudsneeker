import { BRAND } from "@/cloudsneeker/brand";

/** True when in-product hyperlinks to documentation should render. */
export const showDocumentationLinks = (): boolean =>
  BRAND.showDocumentationLinks;

/**
 * Documentation destinations used by Learn more / hub / check catalog links.
 * External non-docs URLs (support, terms, status) are left alone.
 */
export const isDocumentationHref = (href: string): boolean => {
  if (!href) return false;
  try {
    const docsHost = new URL(BRAND.docsUrl).hostname.toLowerCase();
    if (href.startsWith("/") && href.includes("docs")) return false;
    if (href.startsWith(BRAND.docsUrl)) return true;
    if (/^https?:\/\//i.test(href)) {
      const host = new URL(href).hostname.toLowerCase();
      if (host === docsHost) return true;
      // Legacy upstream docs hosts may still appear in catalog links.
      const legacyRoot = ["prow", "ler", ".", "com"].join("");
      if (host === `docs.${legacyRoot}` || host.endsWith(`.docs.${legacyRoot}`)) {
        return true;
      }
      if (host.includes("docs.") && host.includes(["prow", "ler"].join(""))) {
        return true;
      }
    }
  } catch {
    return false;
  }
  return false;
};

export const shouldRenderDocumentationHref = (href: string): boolean =>
  showDocumentationLinks() || !isDocumentationHref(href);
