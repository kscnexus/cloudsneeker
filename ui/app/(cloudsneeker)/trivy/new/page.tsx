import { ScanSearch } from "lucide-react";

import { getProviders } from "@/actions/providers/providers";
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
    <ContentLayout title="New Trivy target" icon={<ScanSearch />}>
      <TrivyTargetForm providers={providers} />
    </ContentLayout>
  );
}
