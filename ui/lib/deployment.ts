import { BRAND } from "@/cloudsneeker/brand"; // cloudsneeker-hook

import { isCloud } from "./shared/env";

export const PROWLER_CLOUD_ONLY_TOOLTIP = BRAND.unavailableFeatureCopy;

export const isGroupedJiraDispatchEnabled = (): boolean => isCloud();
