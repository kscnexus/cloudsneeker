import { describe, expect, it } from "vitest";

import { BRAND } from "@/cloudsneeker/brand";

import { canonicalToolName, isSameToolName } from "./lighthouse-tools";

const brandTool = `${BRAND.mcpToolNamespace}_search_security_findings`;

describe("canonicalToolName", () => {
  it("maps the shipped MCP tool name to the upstream name", () => {
    expect(canonicalToolName(brandTool)).toBe(
      "prowler_search_security_findings",
    );
  });

  it("leaves upstream and unrelated names alone", () => {
    expect(canonicalToolName("prowler_search_security_findings")).toBe(
      "prowler_search_security_findings",
    );
    expect(canonicalToolName("describe_tool")).toBe("describe_tool");
  });
});

describe("isSameToolName", () => {
  it("matches a prompt name against the shipped MCP name", () => {
    expect(isSameToolName(brandTool, "prowler_search_security_findings")).toBe(
      true,
    );
  });

  it("does not match different tools", () => {
    expect(isSameToolName(brandTool, "prowler_list_scans")).toBe(false);
  });
});
