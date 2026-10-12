import { BRAND, docsUrl } from "./brand";

const SOURCES_HEADING = "## Sources and Domain Knowledge";

const UPSTREAM_TIER_NAMES = /\bProwler (?:Cloud|Local Server|Hub|Docs|App)\b/g;
const UPSTREAM_NAME = /\bProwler\b/g;

const sourcesSection = (): string =>
  [
    SOURCES_HEADING,
    "",
    `- ${BRAND.name} website: ${BRAND.websiteUrl}`,
    `- ${BRAND.name} documentation: ${docsUrl()}`,
    `- ${BRAND.name} support: ${BRAND.supportUrl}`,
    "",
  ].join("\n");

/**
 * Rewrites the upstream Lighthouse system prompt so the agent presents
 * itself as the product and only cites product-owned sources.
 */
export const brandSystemPrompt = (template: string): string => {
  const headingIndex = template.indexOf(SOURCES_HEADING);
  const body = headingIndex === -1 ? template : template.slice(0, headingIndex);
  const branded = body
    .replace(UPSTREAM_TIER_NAMES, BRAND.name)
    .replace(UPSTREAM_NAME, BRAND.name);
  return `${branded}${sourcesSection()}`;
};
