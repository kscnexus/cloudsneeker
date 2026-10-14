import { BRAND } from "@/cloudsneeker/brand"; // cloudsneeker-hook
import { isCloudsneekerFeatureEnabled } from "@/cloudsneeker/features"; // cloudsneeker-hook

import { isCloud } from "./shared/env";

export const PROWLER_CLOUD_ONLY_TOOLTIP = BRAND.unavailableFeatureCopy;

export const isGroupedJiraDispatchEnabled = (): boolean =>
  isCloud() || isCloudsneekerFeatureEnabled("jiraGroupedDispatch"); // cloudsneeker-hook
