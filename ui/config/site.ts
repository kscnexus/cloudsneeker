// cloudsneeker-hook: product identity comes from ui/cloudsneeker/brand.ts
import { BRAND } from "@/cloudsneeker/brand";

export type SiteConfig = typeof siteConfig;

export const siteConfig = {
  name: BRAND.name,
  description: `${BRAND.name} automates security and compliance across cloud environments. It runs ready-to-use security checks, remediation guidance, and compliance frameworks, and presents findings in assessments, dashboards, and reports.`,
};
