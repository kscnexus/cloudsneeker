"use client";

import { useRouter } from "next/navigation";
import type { ReactNode } from "react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/shadcn";

export interface ProductPageTab {
  value: string;
  label: string;
  href: string;
  content: ReactNode;
}

interface ProductPageTabsProps {
  activeTab: string;
  tabs: ProductPageTab[];
  /** Buttons on the right of the tab bar. */
  actions?: ReactNode;
}

/**
 * Dashboard-style tab bar shared by the product areas (Application Security,
 * like Cloud Governance): tabs on the left, actions on the right, and the tab
 * kept in the URL so it survives reloads and links.
 */
export const ProductPageTabs = ({
  activeTab,
  tabs,
  actions,
}: ProductPageTabsProps) => {
  const router = useRouter();

  const handleTabChange = (value: string) => {
    if (value === activeTab) return;
    const tab = tabs.find((item) => item.value === value);
    if (tab) router.push(tab.href);
  };

  return (
    <Tabs value={activeTab} onValueChange={handleTabChange}>
      <div className="flex flex-col gap-[18px]">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
          <TabsList className="sm:w-auto sm:flex-1">
            {tabs.map((tab) => (
              <TabsTrigger key={tab.value} value={tab.value}>
                {tab.label}
              </TabsTrigger>
            ))}
          </TabsList>
          {actions ? <div className="shrink-0">{actions}</div> : null}
        </div>
        {tabs.map((tab) => (
          <TabsContent key={tab.value} value={tab.value}>
            {tab.content}
          </TabsContent>
        ))}
      </div>
    </Tabs>
  );
};
