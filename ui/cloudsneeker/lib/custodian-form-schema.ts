import { z } from "zod";

import {
  CUSTODIAN_SCHEDULE_PRESET,
  cronFromPreset,
} from "@/cloudsneeker/lib/custodian-schedule";

const POLICY_YAML_MIN = 20;

const fiveFieldCron = z
  .string()
  .trim()
  .refine((value) => value.split(/\s+/).length === 5, {
    message: "Custom cron must have 5 fields",
  });

export const custodianPolicyFormSchema = z
  .object({
    name: z
      .string()
      .trim()
      .min(3, "Name must be at least 3 characters")
      .max(100, "Name must be at most 100 characters"),
    description: z.string().max(2000).default(""),
    providerId: z.uuid("Select a supported cloud provider"),
    policyYaml: z
      .string()
      .trim()
      .min(POLICY_YAML_MIN, "Policy YAML is required")
      .refine((value) => value.includes("policies:"), {
        message: "YAML must include a policies list",
      }),
    schedulePreset: z
      .enum([
        CUSTODIAN_SCHEDULE_PRESET.DISABLED,
        CUSTODIAN_SCHEDULE_PRESET.HOURLY,
        CUSTODIAN_SCHEDULE_PRESET.DAILY,
        CUSTODIAN_SCHEDULE_PRESET.WEEKLY,
        CUSTODIAN_SCHEDULE_PRESET.CUSTOM,
      ])
      .default(CUSTODIAN_SCHEDULE_PRESET.DISABLED),
    scheduleHour: z.coerce.number().int().min(0).max(23).default(9),
    scheduleWeekday: z.coerce.number().int().min(0).max(6).default(1),
    scheduleTimezone: z.string().trim().min(1).default("UTC"),
    scheduleCron: z.string().default(""),
    regionsOverride: z.string().default(""),
  })
  .superRefine((values, ctx) => {
    if (values.schedulePreset === CUSTODIAN_SCHEDULE_PRESET.CUSTOM) {
      const parsed = fiveFieldCron.safeParse(values.scheduleCron);
      if (!parsed.success) {
        ctx.addIssue({
          code: "custom",
          path: ["scheduleCron"],
          message: "Custom cron must have 5 fields",
        });
      }
    }
  })
  .transform((values) => {
    const mapped = cronFromPreset({
      preset: values.schedulePreset,
      hour: values.scheduleHour,
      weekday: values.scheduleWeekday,
      customCron: values.scheduleCron,
    });
    const regionsOverride = values.regionsOverride
      .split(/[,\s]+/)
      .map((region) => region.trim())
      .filter(Boolean);
    return {
      ...values,
      scheduleEnabled: mapped.enabled,
      scheduleCron: mapped.cron,
      regionsOverrideList: regionsOverride,
    };
  });

export type CustodianPolicyFormInput = z.input<typeof custodianPolicyFormSchema>;
export type CustodianPolicyFormValues = z.output<
  typeof custodianPolicyFormSchema
>;
