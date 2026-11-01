import { beforeEach, describe, expect, it, vi } from "vitest";

import { generateSbomFromDescription } from "./sbom";

const { tenantConfigMock, credentialsMock, invokeMock, createLLMMock } =
  vi.hoisted(() => ({
    tenantConfigMock: vi.fn(),
    credentialsMock: vi.fn(),
    invokeMock: vi.fn(),
    createLLMMock: vi.fn(),
  }));

vi.mock("@/actions/lighthouse-v1/lighthouse", () => ({
  getTenantConfig: tenantConfigMock,
  getProviderCredentials: credentialsMock,
}));

vi.mock("@/lib/lighthouse-v1/llm-factory", () => ({
  createLLM: createLLMMock,
}));

const configured = () => {
  tenantConfigMock.mockResolvedValue({
    data: {
      attributes: {
        default_provider: "openai",
        default_models: { openai: "gpt-5.2" },
      },
    },
  });
  credentialsMock.mockResolvedValue({ credentials: { api_key: "test" } });
};

describe("generateSbomFromDescription", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    createLLMMock.mockReturnValue({ invoke: invokeMock });
  });

  it("builds an SBOM from the components the model extracts", async () => {
    configured();
    invokeMock.mockResolvedValue({
      content:
        '```json\n{"components":[{"name":"org.apache.logging.log4j:log4j-core","version":"2.14.1","ecosystem":"maven"},{"name":"react","version":null,"ecosystem":"npm"}]}\n```',
    });

    const result = await generateSbomFromDescription(
      "billing uses Log4j 2.14.1 and React",
    );

    expect(createLLMMock).toHaveBeenCalledWith(
      expect.objectContaining({ provider: "openai", model: "gpt-5.2" }),
    );
    expect(result).toMatchObject({
      components: [
        {
          name: "org.apache.logging.log4j:log4j-core",
          version: "2.14.1",
          ecosystem: "maven",
        },
      ],
      skipped: ["react"],
    });
    if ("sbom" in result) {
      expect(JSON.parse(result.sbom).components[0].purl).toBe(
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      );
    }
  });

  it("explains when Seeker AI is not set up", async () => {
    tenantConfigMock.mockResolvedValue({ data: { attributes: {} } });
    credentialsMock.mockResolvedValue({ credentials: {} });

    const result = await generateSbomFromDescription("lodash 4.17.20");

    expect(result).toEqual({
      error: expect.stringContaining("Seeker AI is not set up"),
    });
    expect(createLLMMock).not.toHaveBeenCalled();
  });

  it("asks for versions when none are stated", async () => {
    configured();
    invokeMock.mockResolvedValue({
      content:
        '{"components":[{"name":"lodash","version":null,"ecosystem":"npm"}]}',
    });

    expect(await generateSbomFromDescription("we use lodash")).toEqual({
      error: "No exact versions found. Add versions for: lodash.",
    });
  });

  it("rejects empty input and model failures", async () => {
    expect(await generateSbomFromDescription("  ")).toEqual({
      error: "Describe the components to include.",
    });

    configured();
    invokeMock.mockRejectedValue(new Error("quota"));
    vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await generateSbomFromDescription("lodash 4.17.20")).toEqual({
      error: "Seeker AI could not generate the SBOM. Try again in a moment.",
    });
  });
});
