import { describe, expect, it } from "vitest";

import { resourcesToCsv, resourcesToJson } from "./custodian-export";

const RESOURCE = {
  id: "vol-1-0",
  uid: "vol-1",
  name: "orphaned-disk",
  type: "aws.ebs",
  region: "us-east-1",
  service: "ebs",
  policyName: "unused-ebs",
  status: "available",
  tags: { Name: "orphaned-disk" },
  raw: { VolumeId: "vol-1" },
};

describe("custodian-export", () => {
  it("exports CSV with a header row", () => {
    const csv = resourcesToCsv([RESOURCE]);
    expect(csv).toContain("uid,name,type,service,region,status,policy");
    expect(csv).toContain("vol-1,orphaned-disk,aws.ebs,ebs,us-east-1,available,unused-ebs");
  });

  it("exports JSON with raw payload", () => {
    const json = resourcesToJson([RESOURCE]);
    const parsed = JSON.parse(json) as Array<{ uid: string; raw: { VolumeId: string } }>;
    expect(parsed[0].uid).toBe("vol-1");
    expect(parsed[0].raw.VolumeId).toBe("vol-1");
  });
});
