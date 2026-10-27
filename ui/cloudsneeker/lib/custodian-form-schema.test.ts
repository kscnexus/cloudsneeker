import { describe, expect, it } from "vitest";

import { custodianPolicyFormSchema } from "./custodian-form-schema";
import { CUSTODIAN_SCHEDULE_PRESET } from "./custodian-schedule";

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
    if (parsed.success) {
      expect(parsed.data.scheduleEnabled).toBe(false);
      expect(parsed.data.regionsOverrideList).toStrictEqual([]);
    }
  });

  it("parses comma-separated region overrides", () => {
    const parsed = custodianPolicyFormSchema.safeParse({
      ...VALID,
      regionsOverride: "us-east-1, eu-west-1",
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.regionsOverrideList).toStrictEqual([
        "us-east-1",
        "eu-west-1",
      ]);
    }
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

  it("maps daily preset to cron", () => {
    const parsed = custodianPolicyFormSchema.safeParse({
      ...VALID,
      schedulePreset: CUSTODIAN_SCHEDULE_PRESET.DAILY,
      scheduleHour: 7,
      scheduleTimezone: "America/New_York",
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.scheduleEnabled).toBe(true);
      expect(parsed.data.scheduleCron).toBe("0 7 * * *");
      expect(parsed.data.scheduleTimezone).toBe("America/New_York");
    }
  });

  it("rejects custom cron without five fields", () => {
    const parsed = custodianPolicyFormSchema.safeParse({
      ...VALID,
      schedulePreset: CUSTODIAN_SCHEDULE_PRESET.CUSTOM,
      scheduleCron: "0 9 * *",
    });
    expect(parsed.success).toBe(false);
  });
});
