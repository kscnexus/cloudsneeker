import { BRAND } from "@/cloudsneeker/brand";

const UPSTREAM_TOOL_PREFIX = "prowler_";

/**
 * Canonical (upstream) form of a Seeker AI tool name.
 *
 * The shipped MCP server names its tools `<mcpToolNamespace>_<tool>`, while
 * the allowlist, system prompt, and tool examples use the upstream
 * `prowler_<tool>` names. Comparing canonical names lets either form resolve.
 */
export const canonicalToolName = (name: string): string => {
  const brandPrefix = `${BRAND.mcpToolNamespace}_`;
  return name.startsWith(brandPrefix)
    ? `${UPSTREAM_TOOL_PREFIX}${name.slice(brandPrefix.length)}`
    : name;
};

export const isSameToolName = (left: string, right: string): boolean =>
  canonicalToolName(left) === canonicalToolName(right);
