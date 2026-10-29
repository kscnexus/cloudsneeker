import { ScanSearch } from "lucide-react";

import { getProviders } from "@/actions/providers/providers";
import { BRAND } from "@/cloudsneeker/brand";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { TrivyTargetForm } from "@/cloudsneeker/components/trivy-target-form";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function NewTrivyTargetPage() {
  const providersResponse = await getProviders({ pageSize: 100 });
  const providers = (providersResponse?.data ?? []).map((provider) => ({
    id: provider.id,
    providerType: provider.attributes.provider,
    label: [
      provider.attributes.provider,
      provider.attributes.alias || provider.attributes.uid || provider.id,
    ]
      .filter(Boolean)
      .join(" · "),
  }));

  return (
    <ContentLayout
      title={`New ${BRAND.appSecurityName} target`}
      icon={<ScanSearch />}
    >
      <PageHeader description="Pick what to scan and the connected source it reads. Findings land in Findings with the rest of your results." />
      <TrivyTargetForm providers={providers} />
    </ContentLayout>
  );
}
