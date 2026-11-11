import { BRAND, docsUrl } from "./brand";

const SOURCES_HEADING = "## Sources and Domain Knowledge";

const UPSTREAM_TIER_NAMES = /\bProwler (?:Cloud|Local Server|Hub|Docs|App)\b/g;
const UPSTREAM_NAME = /\bProwler\b/g;
const ASSISTANT_PHRASE = /\bLighthouse AI\b/g;
const ASSISTANT_WORD = /\bLighthouse\b/g;

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
/**
 * Retries for Seeker AI model calls. LangChain's default (6, exponential
 * backoff) kept a quota or auth error spinning for about two minutes before
 * the chat showed it; one retry still covers a transient blip.
 */
export const SEEKER_AI_MAX_RETRIES = 1;

/** What the assistant covers beyond cloud posture, and how to stay factual. */
export const MODULES_SECTION = [
  "## Product Modules",
  "",
  `${BRAND.name} has three security modules. Answer for all of them, not only cloud accounts:`,
  "",
  `- ${BRAND.cloudSecurityName}: cloud accounts, resources, checks, compliance and attack paths. Use the finding, resource, scan, compliance and attack path tools.`,
  `- ${BRAND.appSecurityName}: applications, repositories, container images, dependencies, SBOMs, secrets, IaC misconfigurations, licenses and code findings. Use the search_area_findings tool with area=application_security, get_application_security_overview, and get_application_security_finding for one finding.`,
  `- ${BRAND.governanceName}: governance policies and the cloud resources each policy matched. Use list_governance_policies and the search_area_findings tool with area=governance.`,
  "",
  "For a platform-wide posture summary or a comparison between modules, call get_platform_posture_summary first.",
  "",
  'Page context: when the current page path is /application-security/findings/<id>, the user is looking at that finding; fetch it with get_application_security_finding before answering "how do I fix this". On /governance/<policy id>/... the user is looking at that policy.',
  "",
  "Accuracy: only report findings, counts and assets that a tool returned. Name the module and the page each fact comes from (the source field of the tool result). Label your own advice as a recommendation, separate from the data. If a module is unavailable to the user, say so instead of guessing.",
  "",
].join("\n");

export const brandSystemPrompt = (template: string): string => {
  const headingIndex = template.indexOf(SOURCES_HEADING);
  const body = headingIndex === -1 ? template : template.slice(0, headingIndex);
  const branded = body
    .replace(ASSISTANT_PHRASE, BRAND.assistantName)
    .replace(ASSISTANT_WORD, BRAND.assistantName)
    .replace(UPSTREAM_TIER_NAMES, BRAND.name)
    .replace(UPSTREAM_NAME, BRAND.name);
  return `${branded}${MODULES_SECTION}\n${sourcesSection()}`;
};
