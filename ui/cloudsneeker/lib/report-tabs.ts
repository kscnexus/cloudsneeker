import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";

export const REPORTS_TAB = {
  REPORTS: "reports",
  SCHEDULES: "schedules",
  SHARE_LINKS: "share-links",
} as const;

export type ReportsTab = (typeof REPORTS_TAB)[keyof typeof REPORTS_TAB];

export const getReportsTab = (
  value: string | string[] | undefined,
): ReportsTab => {
  if (value === REPORTS_TAB.SCHEDULES) return REPORTS_TAB.SCHEDULES;
  if (value === REPORTS_TAB.SHARE_LINKS) return REPORTS_TAB.SHARE_LINKS;
  return REPORTS_TAB.REPORTS;
};

export const buildReportsTabHref = (tab: ReportsTab): string =>
  tab === REPORTS_TAB.REPORTS
    ? PRODUCT_ROUTE.REPORTS
    : `${PRODUCT_ROUTE.REPORTS}?tab=${tab}`;
