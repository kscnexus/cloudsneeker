"use server";

import { HumanMessage, SystemMessage } from "@langchain/core/messages";

import {
  getProviderCredentials,
  getTenantConfig,
} from "@/actions/lighthouse-v1/lighthouse";
import {
  buildCycloneDxSbom,
  extractJsonObject,
  SBOM_DESCRIPTION_MAX_LENGTH,
  SBOM_ECOSYSTEMS,
  SBOM_MAX_COMPONENTS,
  type SbomComponent,
  sanitizeComponents,
} from "@/cloudsneeker/lib/sbom-builder";
import { createLLM, type ProviderType } from "@/lib/lighthouse-v1/llm-factory";
import { getModelParams } from "@/lib/lighthouse-v1/utils";

const SYSTEM_PROMPT = `You extract software components for a Software Bill of Materials.
Read the user's description and list every third-party package it names.
Reply with JSON only, no prose and no code fence, in this shape:
{"components":[{"name":"lodash","version":"4.17.20","ecosystem":"npm"}]}
Rules:
- ecosystem is one of: ${SBOM_ECOSYSTEMS.join(", ")}.
- Maven names are "groupId:artifactId" (for example "org.apache.logging.log4j:log4j-core").
- Use only versions the description states. Never guess a version; set "version": null when none is given.
- Map well-known product names to their package (for example "Log4j 2.14.1" is maven org.apache.logging.log4j:log4j-core 2.14.1, "Django 3.2" is pypi django 3.2).
- At most ${SBOM_MAX_COMPONENTS} components.`;

export interface GeneratedSbom {
  sbom: string;
  components: SbomComponent[];
  skipped: string[];
}

const messageText = (content: unknown): string => {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((part) =>
        typeof part === "string"
          ? part
          : typeof part?.text === "string"
            ? part.text
            : "",
      )
      .join("");
  }
  return "";
};

/**
 * CycloneDX SBOM for the components a plain-language description names,
 * extracted by the organization's Seeker AI model.
 */
export const generateSbomFromDescription = async (
  description: string,
): Promise<GeneratedSbom | { error: string }> => {
  const text = description.trim();
  if (!text) return { error: "Describe the components to include." };
  if (text.length > SBOM_DESCRIPTION_MAX_LENGTH) {
    return {
      error: `Keep the description under ${SBOM_DESCRIPTION_MAX_LENGTH} characters.`,
    };
  }

  const tenantConfig = (await getTenantConfig())?.data?.attributes;
  const providerType = (tenantConfig?.default_provider ||
    "openai") as ProviderType;
  const model = tenantConfig?.default_models?.[providerType];
  const { credentials, base_url: baseUrl } =
    await getProviderCredentials(providerType);
  if (!model || Object.keys(credentials).length === 0) {
    return {
      error:
        "Seeker AI is not set up for this organization. Configure it under Seeker AI settings, or upload an SBOM or dependency file instead.",
    };
  }

  try {
    const llm = createLLM({
      provider: providerType,
      model,
      credentials,
      baseUrl,
      streaming: false,
      tags: ["sbom-generator"],
      modelParams: getModelParams({ model }),
    });
    const reply = await llm.invoke([
      new SystemMessage(SYSTEM_PROMPT),
      new HumanMessage(text),
    ]);
    const parsed = extractJsonObject(messageText(reply.content)) as {
      components?: unknown;
    } | null;
    const { components, skipped } = sanitizeComponents(parsed?.components);
    if (components.length === 0) {
      return {
        error:
          skipped.length > 0
            ? `No exact versions found. Add versions for: ${skipped.join(", ")}.`
            : "No packages found in the description. Name each package and its version.",
      };
    }
    return { sbom: buildCycloneDxSbom(components), components, skipped };
  } catch (error) {
    console.error("[Server] SBOM generation failed:", error);
    return {
      error: "Seeker AI could not generate the SBOM. Try again in a moment.",
    };
  }
};
