export const LAUNCH_SCAN_SEARCH_PARAM = "launchScan";
export const LAUNCH_SCAN_SEARCH_VALUE = "true";
export const LAUNCH_SCAN_HREF = `/scans?${LAUNCH_SCAN_SEARCH_PARAM}=${LAUNCH_SCAN_SEARCH_VALUE}`;

export const IMPORT_FINDINGS_SEARCH_PARAM = "import";
export const isImportFindingsSearchParam = (value: string | null): boolean =>
  value === "1" || value === "true";

