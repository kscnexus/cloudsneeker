"use client";

import { useRouter } from "next/navigation";
import { ReactNode } from "react";

import {
  buildCustodianTabHref,
  CUSTODIAN_TAB,
  type CustodianTab,
} from "@/cloudsneeker/lib/custodian-dashboard";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/shadcn";

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
}: CustodianPageTabsProps) => {
  const router = useRouter();

  const handleTabChange = (tab: string) => {
    const typedTab = tab as CustodianTab;
    if (typedTab === activeTab) return;
    router.push(buildCustodianTabHref(typedTab));
  };

  return (
    <Tabs value={activeTab} onValueChange={handleTabChange}>
      <div className="flex flex-col gap-[18px]">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <TabsList>
            <TabsTrigger value={CUSTODIAN_TAB.DASHBOARD}>Dashboard</TabsTrigger>
            <TabsTrigger value={CUSTODIAN_TAB.POLICIES}>Policies</TabsTrigger>
            <TabsTrigger value={CUSTODIAN_TAB.REPORTS}>Reports</TabsTrigger>
          </TabsList>
          {actions}
        </div>

        <TabsContent value={CUSTODIAN_TAB.DASHBOARD}>
          {dashboardContent}
        </TabsContent>
        <TabsContent value={CUSTODIAN_TAB.POLICIES}>
          {policiesContent}
        </TabsContent>
        <TabsContent value={CUSTODIAN_TAB.REPORTS}>
          {reportsContent}
        </TabsContent>
      </div>
    </Tabs>
  );
};
