"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { LighthouseV2SidebarChat } from "@/app/(prowler)/lighthouse/_components/navigation";
import { BRAND } from "@/cloudsneeker/brand"; // cloudsneeker-hook
import { useCloudsneekerPlan } from "@/cloudsneeker/lib/plan-store"; // cloudsneeker-hook
import { withCloudsneekerPlan } from "@/cloudsneeker/navigation"; // cloudsneeker-hook
import { ProwlerBrand } from "@/components/icons";
import { useAuth } from "@/hooks";
import { useRuntimeConfig } from "@/hooks/use-runtime-config";
import { isCloud } from "@/lib/shared/env";
import { useUIStore } from "@/store/ui/store";

import { useHydratedAppSidebarMode } from "./app-sidebar-mode-store";
import { AppSidebarModeToggle } from "./app-sidebar-mode-toggle";
import { LaunchScanAction } from "./launch-scan-action";
import { getNavigationConfig } from "./navigation-config";
import { SidebarFooter } from "./sidebar-footer";
import { SidebarNavigation } from "./sidebar-navigation";
import { APP_SIDEBAR_MODE, type AppSidebarSelectionHandler } from "./types";

interface AppSidebarContentProps {
  onSelect?: AppSidebarSelectionHandler;
}

export function AppSidebarContent({ onSelect }: AppSidebarContentProps) {
  const pathname = usePathname();
  const { permissions } = useAuth();
  // One-time server decision per request, seeded by the root layout.
  const registryEligible = useUIStore((state) => state.registryEligible);
  const { apiDocsUrl, cloudBillingEnabled } = useRuntimeConfig();
  const mode = useHydratedAppSidebarMode();
  const isCloudEnvironment = isCloud();
  const cloudsneekerPlan = useCloudsneekerPlan(); // cloudsneeker-hook
  // cloudsneeker-hook: plan features and the operator link wrap the upstream sections
  const sections = withCloudsneekerPlan(
    getNavigationConfig({
      pathname,
      apiDocsUrl,
      cloudBillingEnabled,
      registryEligible,
      permissions,
    }),
    cloudsneekerPlan,
  );
  const showChat = isCloudEnvironment && mode === APP_SIDEBAR_MODE.CHAT;

  return (
    <div className="relative flex h-full min-h-0 w-full flex-col overflow-hidden">
      <div className="shrink-0 px-5 pt-8 pb-7">
        <Link
          href="/"
          aria-label={`${BRAND.name} home`} // cloudsneeker-hook
          className="focus-visible:ring-button-primary/50 flex h-8 items-center rounded-md focus-visible:ring-2 focus-visible:outline-none"
          onClick={onSelect}
        >
          <ProwlerBrand />
        </Link>
      </div>

      <div className="shrink-0 space-y-3 px-3 pb-1">
        <LaunchScanAction onSelect={onSelect} />
        {(isCloudEnvironment || BRAND.showUpsell) && ( // cloudsneeker-hook
          <AppSidebarModeToggle
            chatEnabled={isCloudEnvironment}
            onSelect={onSelect}
          />
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-hidden">
        {showChat ? (
          <LighthouseV2SidebarChat isOpen />
        ) : (
          <SidebarNavigation sections={sections} onSelect={onSelect} />
        )}
      </div>

      <SidebarFooter
        isCloudEnvironment={isCloudEnvironment}
        onSelect={onSelect}
      />
    </div>
  );
}
