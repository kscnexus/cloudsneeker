import { describe, expect, it } from "vitest";

import { custodianPolicyFormSchema } from "./custodian-form-schema";

const VALID = {
  name: "unused-ebs",
  description: "Find unattached volumes",
  providerId: "11111111-1111-4111-8111-111111111111",
  policyYaml: `policies:
  - name: unused-ebs
    resource: aws.ebs
    filters:
      - Attachments: []
`,
};

describe("custodianPolicyFormSchema", () => {
  it("accepts a valid Custodian policy form", () => {
    const parsed = custodianPolicyFormSchema.safeParse(VALID);
    expect(parsed.success).toBe(true);
  });

  it("rejects a short name", () => {
    const parsed = custodianPolicyFormSchema.safeParse({
      ...VALID,
      name: "ab",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects YAML without a policies key", () => {
    const parsed = custodianPolicyFormSchema.safeParse({
      ...VALID,
      policyYaml: "name: alone\nresource: aws.ebs\n",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects an invalid provider id", () => {
    const parsed = custodianPolicyFormSchema.safeParse({
      ...VALID,
      providerId: "not-a-uuid",
    });
    expect(parsed.success).toBe(false);
  });
});
