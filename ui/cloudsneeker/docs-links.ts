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
      if (host === "docs.prowler.com" || host.endsWith(".docs.prowler.com")) {
        return true;
      }
      if (host.includes("docs.") && host.includes("prowler")) return true;
    }
  } catch {
    return false;
  }
  return false;
};

export const shouldRenderDocumentationHref = (href: string): boolean =>
  showDocumentationLinks() || !isDocumentationHref(href);
