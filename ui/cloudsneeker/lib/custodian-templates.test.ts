import { describe, expect, it } from "vitest";

import {
  findingsHrefForChecks,
  packsForProvider,
  templatesForProwlerChecks,
  templatesForProvider,
} from "./custodian-templates";

describe("custodian templates", () => {
  it("filters templates by provider", () => {
    const aws = templatesForProvider("aws");
    expect(aws.some((item) => item.id === "aws-public-s3")).toBe(true);
    expect(aws.every((item) => item.providerTypes.includes("aws"))).toBe(true);
  });

  it("returns the aws hygiene pack", () => {
    const packs = packsForProvider("aws");
    expect(packs[0]?.id).toBe("aws-hygiene");
  });

  it("builds a findings deep link", () => {
    expect(findingsHrefForChecks(["s3_bucket_public_access"])).toBe(
      "/findings?filter%5Bcheck_id%5D=s3_bucket_public_access",
    );
    expect(findingsHrefForChecks([])).toBeNull();
  });

  it("maps prowler checks to starter templates", () => {
    const matched = templatesForProwlerChecks(["s3_bucket_public_access"]);
    expect(matched.map((item) => item.id)).toContain("aws-public-s3");
  });
});
