import { BRAND } from "./brand";
import { PRODUCT_ROUTE } from "./routes";

const UUID_SEGMENT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const ID_SEGMENT_LABEL = "Details";

// Product areas read with their product names ("Cloud Governance", not
// "Governance").
const PRODUCT_SEGMENT_LABELS: Record<string, string> = {
  [PRODUCT_ROUTE.APPLICATION_SECURITY.slice(1)]: BRAND.appSecurityName,
  [PRODUCT_ROUTE.GOVERNANCE.slice(1)]: BRAND.governanceName,
};

/**
 * Label for an auto-generated breadcrumb segment. Record ids in nested
 * routes (for example `/application-security/<targetId>/runs/<runId>`) read
 * as "Details" instead of a split-up UUID.
 */
export const breadcrumbSegmentLabel = (
  segment: string,
  fallback: string,
): string => {
  if (UUID_SEGMENT.test(segment)) return ID_SEGMENT_LABEL;
  return PRODUCT_SEGMENT_LABELS[segment] ?? fallback;
};
