import { describe, expect, it } from "vitest";

import {
  extractCustodianResourceUid,
  normalizeCustodianResources,
} from "./custodian-resources";

describe("extractCustodianResourceUid", () => {
  it("prefers cloud-native identifiers", () => {
    expect(extractCustodianResourceUid({ VolumeId: "vol-abc" })).toBe("vol-abc");
    expect(extractCustodianResourceUid({ InstanceId: "i-1" })).toBe("i-1");
    expect(extractCustodianResourceUid({ Arn: "arn:aws:ec2:…" })).toBe(
      "arn:aws:ec2:…",
    );
    expect(extractCustodianResourceUid({ id: "/subscriptions/x/vm" })).toBe(
      "/subscriptions/x/vm",
    );
  });
});

describe("normalizeCustodianResources", () => {
  it("maps AWS EBS-style resources into finding-like rows", () => {
    const rows = normalizeCustodianResources({
      resources: [
        {
          VolumeId: "vol-1",
          AvailabilityZone: "us-east-1a",
          State: "available",
          Size: 100,
          Tags: [
            { Key: "Name", Value: "orphaned-disk" },
            { Key: "env", Value: "dev" },
          ],
          "c7n:region": "us-east-1",
          "c7n:policy": "unused-ebs",
        },
      ],
      policies: [{ name: "unused-ebs", resource_count: 1 }],
    });

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      uid: "vol-1",
      name: "orphaned-disk",
      region: "us-east-1",
      policyName: "unused-ebs",
      status: "available",
      tags: { Name: "orphaned-disk", env: "dev" },
    });
    expect(rows[0].type).toMatch(/ebs|volume|aws/i);
  });

  it("returns an empty list when output has no resources", () => {
    expect(normalizeCustodianResources({})).toEqual([]);
    expect(normalizeCustodianResources({ resources: [] })).toEqual([]);
  });

  it("falls back to Name tag and path metadata", () => {
    const rows = normalizeCustodianResources({
      resources: [
        {
          Id: "bucket-1",
          Name: "logs-bucket",
          LocationConstraint: "eu-west-1",
        },
      ],
    });
    expect(rows[0].uid).toBe("bucket-1");
    expect(rows[0].name).toBe("logs-bucket");
    expect(rows[0].region).toBe("eu-west-1");
  });
});
