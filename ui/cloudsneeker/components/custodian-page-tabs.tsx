import { ReactNode } from "react";

import {
  buildCustodianTabHref,
  CUSTODIAN_TAB,
  type CustodianTab,
} from "@/cloudsneeker/lib/custodian-dashboard";

import { ProductPageTabs } from "./product-page-tabs";

interface CustodianPageTabsProps {
  activeTab: CustodianTab;
  dashboardContent: ReactNode;
  policiesContent: ReactNode;
  reportsContent: ReactNode;
  actions?: ReactNode;
}

export const CustodianPageTabs = ({
  activeTab,
  dashboardContent,
  policiesContent,
  reportsContent,
  actions,
}: CustodianPageTabsProps) => (
  <ProductPageTabs
    activeTab={activeTab}
    actions={actions}
    tabs={[
      {
        value: CUSTODIAN_TAB.DASHBOARD,
        label: "Dashboard",
        href: buildCustodianTabHref(CUSTODIAN_TAB.DASHBOARD),
        content: dashboardContent,
      },
      {
        value: CUSTODIAN_TAB.POLICIES,
        label: "Policies",
        href: buildCustodianTabHref(CUSTODIAN_TAB.POLICIES),
        content: policiesContent,
      },
      {
        value: CUSTODIAN_TAB.REPORTS,
        label: "Reports",
        href: buildCustodianTabHref(CUSTODIAN_TAB.REPORTS),
        content: reportsContent,
      },
    ]}
  />
);
