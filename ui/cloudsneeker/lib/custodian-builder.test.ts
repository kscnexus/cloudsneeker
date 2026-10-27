import { describe, expect, it } from "vitest";

import {
  CUSTODIAN_BUILDER_RESOURCE,
  buildCustodianPolicyYaml,
  filtersForResource,
} from "./custodian-builder";

describe("custodian builder", () => {
  it("lists s3 filters", () => {
    expect(
      filtersForResource(CUSTODIAN_BUILDER_RESOURCE.AWS_S3).length,
    ).toBeGreaterThan(0);
  });

  it("builds yaml with a single filter", () => {
    const yaml = buildCustodianPolicyYaml({
      name: "unused-ebs",
      resource: CUSTODIAN_BUILDER_RESOURCE.AWS_EBS,
      filterIds: ["unattached"],
    });
    expect(yaml).toContain("resource: aws.ebs");
    expect(yaml).toContain("Attachments: []");
    expect(yaml).not.toContain("actions:");
  });

  it("builds yaml with or when multiple filters", () => {
    const yaml = buildCustodianPolicyYaml({
      name: "public-s3",
      resource: CUSTODIAN_BUILDER_RESOURCE.AWS_S3,
      filterIds: ["global-grants", "public-block-acls"],
    });
    expect(yaml).toContain("- or:");
    expect(yaml).toContain("global-grants");
    expect(yaml).toContain("BlockPublicAcls: false");
  });
});
