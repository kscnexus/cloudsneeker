import { describe, expect, it } from "vitest";

import { frameworkLabel } from "./report-view";

describe("frameworkLabel", () => {
  it("names frameworks and their provider", () => {
    expect(frameworkLabel("nis2_aws")).toBe("NIS2 AWS");
    expect(frameworkLabel("ccc_azure")).toBe("CCC Azure");
    expect(frameworkLabel("csa_ccm_4.0_aws")).toBe("CSA CCM 4.0 AWS");
    expect(frameworkLabel("c5_azure")).toBe("C5 Azure");
    expect(frameworkLabel("ens_rd2022_aws")).toBe("ENS RD2022 AWS");
  });
});
