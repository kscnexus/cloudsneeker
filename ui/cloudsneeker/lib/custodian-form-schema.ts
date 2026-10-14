import { z } from "zod";

const POLICY_YAML_MIN = 20;

export const custodianPolicyFormSchema = z.object({
  name: z
    .string()
    .trim()
    .min(3, "Name must be at least 3 characters")
    .max(100, "Name must be at most 100 characters"),
  description: z.string().max(2000).default(""),
  providerId: z.uuid("Select an AWS provider"),
  policyYaml: z
    .string()
    .trim()
    .min(POLICY_YAML_MIN, "Policy YAML is required")
    .refine((value) => value.includes("policies:"), {
      message: "YAML must include a policies list",
    }),
});

export type CustodianPolicyFormValues = z.infer<typeof custodianPolicyFormSchema>;
