"use client";

import { useRouter } from "next/navigation";
import type { ReactNode } from "react";

import {
  buildReportsTabHref,
  REPORTS_TAB,
  type ReportsTab,
} from "@/cloudsneeker/lib/report-tabs";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/shadcn";

interface ReportPageTabsProps {
  activeTab: ReportsTab;
  reportsContent: ReactNode;
  schedulesContent: ReactNode;
  shareLinksContent: ReactNode;
}

export const ReportPageTabs = ({
  activeTab,
  reportsContent,
  schedulesContent,
  shareLinksContent,
}: ReportPageTabsProps) => {
  const router = useRouter();

  const handleTabChange = (tab: string) => {
    const typedTab = tab as ReportsTab;
    if (typedTab === activeTab) return;
    router.push(buildReportsTabHref(typedTab));
  };

  return (
    <Tabs value={activeTab} onValueChange={handleTabChange}>
      <div className="flex flex-col gap-[18px]">
        <TabsList>
          <TabsTrigger value={REPORTS_TAB.REPORTS}>Reports</TabsTrigger>
          <TabsTrigger value={REPORTS_TAB.SCHEDULES}>Schedules</TabsTrigger>
          <TabsTrigger value={REPORTS_TAB.SHARE_LINKS}>Share links</TabsTrigger>
        </TabsList>
        <TabsContent value={REPORTS_TAB.REPORTS}>{reportsContent}</TabsContent>
        <TabsContent value={REPORTS_TAB.SCHEDULES}>
          {schedulesContent}
        </TabsContent>
        <TabsContent value={REPORTS_TAB.SHARE_LINKS}>
          {shareLinksContent}
        </TabsContent>
      </div>
    </Tabs>
  );
};
