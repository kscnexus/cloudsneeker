const UUID_SEGMENT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const ID_SEGMENT_LABEL = "Details";

/**
 * Label for an auto-generated breadcrumb segment. Record ids in nested
 * routes (for example `/trivy/<targetId>/runs/<runId>`) read as "Details"
 * instead of a split-up UUID.
 */
export const breadcrumbSegmentLabel = (
  segment: string,
  fallback: string,
): string => (UUID_SEGMENT.test(segment) ? ID_SEGMENT_LABEL : fallback);
