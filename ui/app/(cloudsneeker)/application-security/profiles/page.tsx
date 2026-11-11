import { SlidersHorizontal } from "lucide-react";

import { AppSecProfilesManager } from "@/cloudsneeker/components/appsec-profiles-manager";
import { LoadError } from "@/cloudsneeker/components/appsec-ui";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { APPSEC_SEGMENT } from "@/cloudsneeker/lib/appsec";
import {
  canManageScans,
  loadCapabilities,
  loadProfiles,
} from "@/cloudsneeker/lib/appsec-server";
import { appSecurityHref } from "@/cloudsneeker/routes";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function AppSecurityProfilesPage() {
  const [profiles, capabilities, canManage] = await Promise.all([
    loadProfiles(),
    loadCapabilities(),
    canManageScans(),
  ]);
  return (
    <ContentLayout title="Scan profiles" icon={<SlidersHorizontal />}>
      <PageHeader description="Reusable scan settings: which scanners run, which severities are reported, what is skipped, and scanner-specific options. Only options the scan engine accepts for a target type can be saved." />
      {capabilities ? (
        <AppSecProfilesManager
          profiles={profiles}
          capabilities={capabilities}
          canManage={canManage}
        />
      ) : (
        <LoadError
          title="Scan profiles"
          what="Scan profiles"
          reloadHref={appSecurityHref(APPSEC_SEGMENT.PROFILES)}
        />
      )}
    </ContentLayout>
  );
}
