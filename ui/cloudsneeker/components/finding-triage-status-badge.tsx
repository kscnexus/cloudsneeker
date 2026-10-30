import { triageStatusLabel } from "@/cloudsneeker/lib/finding-triage";
import { Badge } from "@/components/shadcn/badge/badge";
import { FINDING_TRIAGE_STATUS } from "@/types/findings-triage";

const TRIAGE_STATUS_VARIANT = {
  [FINDING_TRIAGE_STATUS.OPEN]: "error",
  [FINDING_TRIAGE_STATUS.REOPENED]: "error",
  [FINDING_TRIAGE_STATUS.UNDER_REVIEW]: "warning",
  [FINDING_TRIAGE_STATUS.REMEDIATING]: "info",
  [FINDING_TRIAGE_STATUS.RESOLVED]: "success",
  [FINDING_TRIAGE_STATUS.RISK_ACCEPTED]: "tag",
  [FINDING_TRIAGE_STATUS.FALSE_POSITIVE]: "tag",
} as const;

type TriageStatusVariant =
  (typeof TRIAGE_STATUS_VARIANT)[keyof typeof TRIAGE_STATUS_VARIANT];

export const triageStatusVariant = (status: string): TriageStatusVariant =>
  TRIAGE_STATUS_VARIANT[status as keyof typeof TRIAGE_STATUS_VARIANT] ?? "tag";

/** Triage status pill used on the Triage page. */
export const FindingTriageStatusBadge = ({ status }: { status: string }) => (
  <Badge variant={triageStatusVariant(status)}>
    {triageStatusLabel(status)}
  </Badge>
);
