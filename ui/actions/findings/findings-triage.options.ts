import { isCloudsneekerFeatureEnabled } from "@/cloudsneeker/features"; // cloudsneeker-hook
import { isCloud } from "@/lib/shared/env";
import {
  FINDING_TRIAGE_DISABLED_REASON,
  type FindingTriageDisabledReason,
} from "@/types/findings-triage";

interface FindingTriageAdapterOptions {
  canEdit: boolean;
  disabledReason?: FindingTriageDisabledReason;
}

export function getFindingTriageAdapterOptions(): FindingTriageAdapterOptions {
  const isCloudEnvironment =
    isCloud() || isCloudsneekerFeatureEnabled("findingTriage"); // cloudsneeker-hook

  return {
    canEdit: isCloudEnvironment,
    ...(isCloudEnvironment
      ? {}
      : { disabledReason: FINDING_TRIAGE_DISABLED_REASON.CLOUD_ONLY }),
  };
}
