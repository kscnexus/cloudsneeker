import { z } from "zod";

import { TRIVY_MODE } from "@/cloudsneeker/types/trivy";

export const trivyTargetFormSchema = z
  .object({
    name: z.string().trim().min(3).max(100),
    description: z.string().max(2000).optional().default(""),
    mode: z.enum([
      TRIVY_MODE.IAC,
      TRIVY_MODE.IMAGE,
      TRIVY_MODE.FS,
      TRIVY_MODE.REPO,
      TRIVY_MODE.SBOM,
      TRIVY_MODE.K8S,
    ]),
    providerId: z.uuid(),
    scanners: z.string().optional().default("vuln,misconfig,secret"),
    images: z.string().optional().default(""),
    repositoryUrl: z.string().optional().default(""),
    archiveB64: z.string().optional().default(""),
    sbom: z.string().optional().default(""),
    namespace: z.string().optional().default(""),
    scheduleEnabled: z.boolean().optional().default(false),
    scheduleCron: z.string().optional().default(""),
    scheduleTimezone: z.string().optional().default("UTC"),
  })
  .superRefine((values, ctx) => {
    if (values.mode === TRIVY_MODE.REPO && !values.repositoryUrl.trim()) {
      ctx.addIssue({
        code: "custom",
        path: ["repositoryUrl"],
        message: "Repository URL is required for repo mode.",
      });
    }
    if (values.mode === TRIVY_MODE.FS && !values.archiveB64.trim()) {
      ctx.addIssue({
        code: "custom",
        path: ["archiveB64"],
        message: "Upload a zip or tar archive for filesystem mode.",
      });
    }
    if (values.mode === TRIVY_MODE.SBOM && !values.sbom.trim()) {
      ctx.addIssue({
        code: "custom",
        path: ["sbom"],
        message: "SBOM content is required for sbom mode.",
      });
    }
    if (values.scheduleEnabled && !values.scheduleCron.trim()) {
      ctx.addIssue({
        code: "custom",
        path: ["scheduleCron"],
        message: "Cron is required when the schedule is enabled.",
      });
    }
  });

export type TrivyTargetFormInput = z.input<typeof trivyTargetFormSchema>;
export type TrivyTargetFormValues = z.output<typeof trivyTargetFormSchema>;

export const buildTrivyConfig = (
  values: TrivyTargetFormValues,
): Record<string, unknown> => {
  const scanners = values.scanners
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const config: Record<string, unknown> = { scanners };

  if (values.mode === TRIVY_MODE.IMAGE) {
    const images = values.images
      .split(/[\n,]/)
      .map((item) => item.trim())
      .filter(Boolean);
    if (images.length > 0) {
      config.images = images;
    }
  }
  if (values.mode === TRIVY_MODE.REPO) {
    config.repository_url = values.repositoryUrl.trim();
  }
  if (values.mode === TRIVY_MODE.FS) {
    if (values.archiveB64.trim()) {
      config.archive_b64 = values.archiveB64.trim();
    }
  }
  if (values.mode === TRIVY_MODE.SBOM) {
    config.sbom = values.sbom;
  }
  if (values.mode === TRIVY_MODE.K8S && values.namespace.trim()) {
    config.namespace = values.namespace.trim();
  }
  return config;
};
