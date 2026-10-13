import { SlidersVertical } from "lucide-react";
import { redirect } from "next/navigation";

import { getProviders } from "@/actions/providers";
import { listScanConfigurations } from "@/actions/scan-configurations";
import { isCloudsneekerFeatureEnabled } from "@/cloudsneeker/features"; // cloudsneeker-hook
import { ContentLayout } from "@/components/shadcn/content-layout";
import { isCloud } from "@/lib/shared/env";

import { ScanConfigurationsManager } from "./_components/scan-configurations-manager";

export default async function ScanConfigPage() {
  // Upstream Cloud-only feature; Cloudsneeker serves matching APIs.
  if (!isCloud() && !isCloudsneekerFeatureEnabled("scanConfiguration")) {
    redirect("/");
  }

  // A failure here propagates to the `(prowler)/error.tsx` boundary instead of
  // rendering a false "no scan configurations" empty table during SSR.
  const [configs, providersResponse] = await Promise.all([
    listScanConfigurations(),
    getProviders({ pageSize: 100 }),
  ]);

  if (!providersResponse) {
    throw new Error("Failed to load Providers for Scan Configuration.");
  }

  const richProviders = providersResponse.data;

  return (
    <ContentLayout title="Scan profiles" icon={<SlidersVertical />}>
      <ScanConfigurationsManager
        initialConfigs={configs}
        richProviders={richProviders}
      />
    </ContentLayout>
  );
}
