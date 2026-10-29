// Product copy for the report catalog. The API catalog supplies ids and
// parameter rules; titles and descriptions here read for managers and never
// name a scanning engine.

import {
  REPORT_TYPE_ID,
  type ReportTypeId,
  type ReportTypeResource,
} from "@/cloudsneeker/types/reports";

export const REPORT_AUDIENCE = {
  MANAGEMENT: "management",
  ENGINEERING: "engineering",
} as const;

export type ReportAudience =
  (typeof REPORT_AUDIENCE)[keyof typeof REPORT_AUDIENCE];

export interface ReportCatalogEntry {
  id: string;
  title: string;
  description: string;
  audience: string;
  requiresFramework: boolean;
}

const REPORT_COPY: Record<ReportTypeId, { title: string; description: string }> =
  {
    [REPORT_TYPE_ID.EXECUTIVE]: {
      title: "Executive summary",
      description:
        "One page for leadership: overall security grade, top business risks, trend, and the next actions that matter most.",
    },
    [REPORT_TYPE_ID.CLOUD_POSTURE]: {
      title: "Cloud posture",
      description:
        "How well your cloud accounts are configured, by severity, service, and account.",
    },
    [REPORT_TYPE_ID.COMPLIANCE]: {
      title: "Compliance",
      description:
        "Requirement-by-requirement status for one framework, ready to hand to an auditor.",
    },
    [REPORT_TYPE_ID.SCA]: {
      title: "Open-source dependencies",
      description:
        "Vulnerable third-party packages with the fixed version to upgrade to.",
    },
    [REPORT_TYPE_ID.SAST]: {
      title: "Source code security",
      description:
        "Weaknesses in your own code such as injection, cross-site scripting, and insecure crypto.",
    },
    [REPORT_TYPE_ID.CONTAINER]: {
      title: "Container images",
      description:
        "Vulnerabilities, exposed secrets, and misconfigurations in images and Kubernetes workloads.",
    },
    [REPORT_TYPE_ID.IAC]: {
      title: "Infrastructure as Code",
      description:
        "Misconfigurations caught in templates before they reach production.",
    },
    [REPORT_TYPE_ID.SECRETS]: {
      title: "Exposed secrets",
      description:
        "Credentials and keys found in code, images, and cloud accounts.",
    },
    [REPORT_TYPE_ID.GOVERNANCE]: {
      title: "Cloud governance",
      description:
        "Resources that break your governance policies and how that changed since the last check.",
    },
  };

const isKnownReportType = (id: string): id is ReportTypeId =>
  Object.values(REPORT_TYPE_ID).includes(id as ReportTypeId);

export const reportTitle = (id: string, fallback?: string): string =>
  isKnownReportType(id) ? REPORT_COPY[id].title : (fallback ?? id);

/** Catalog entries in API order with product copy applied. */
export const buildReportCatalog = (
  types: ReportTypeResource[],
): ReportCatalogEntry[] =>
  types.map((type) => {
    const copy = isKnownReportType(type.id) ? REPORT_COPY[type.id] : null;
    return {
      id: type.id,
      title: copy?.title ?? type.attributes.name,
      description: copy?.description ?? type.attributes.description,
      audience: type.attributes.audience,
      requiresFramework: (type.attributes.parameters?.required ?? []).includes(
        "compliance_id",
      ),
    };
  });
