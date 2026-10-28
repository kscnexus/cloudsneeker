import { describe, expect, it } from "vitest";

import {
  buildTrivyConfig,
  trivyTargetFormSchema,
} from "@/cloudsneeker/lib/trivy-form-schema";
import { TRIVY_MODE } from "@/cloudsneeker/types/trivy";

describe("trivyTargetFormSchema", () => {
  it("requires repository URL for repo mode", () => {
    const result = trivyTargetFormSchema.safeParse({
      name: "repo-scan",
      mode: TRIVY_MODE.REPO,
      providerId: "11111111-1111-4111-8111-111111111111",
      repositoryUrl: "",
    });
    expect(result.success).toBe(false);
  });

  it("builds config for sbom mode", () => {
    const values = trivyTargetFormSchema.parse({
      name: "sbom-scan",
      mode: TRIVY_MODE.SBOM,
      providerId: "11111111-1111-4111-8111-111111111111",
      sbom: '{"bomFormat":"CycloneDX"}',
      scanners: "vuln",
    });
    expect(buildTrivyConfig(values)).toEqual({
      scanners: ["vuln"],
      sbom: '{"bomFormat":"CycloneDX"}',
    });
  });
});
