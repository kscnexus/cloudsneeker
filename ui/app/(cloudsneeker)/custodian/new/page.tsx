import { ShieldPlus } from "lucide-react";

import { getProviders } from "@/actions/providers/providers";
import { CustodianPolicyForm } from "@/cloudsneeker/components/custodian-policy-form";
import { CUSTODIAN_PROVIDER_FILTER } from "@/cloudsneeker/lib/custodian-providers";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function NewCustodianPolicyPage() {
  const providersResponse = await getProviders({
    pageSize: 100,
    filters: { ...CUSTODIAN_PROVIDER_FILTER },
  });

  const providers = (providersResponse?.data ?? []).map((provider) => ({
    id: provider.id,
    label: [
      provider.attributes.provider,
      provider.attributes.alias || provider.attributes.uid || provider.id,
    ]
      .filter(Boolean)
      .join(" · "),
  }));

  return (
    <ContentLayout title="New Custodian policy" icon={<ShieldPlus />}>
      <CustodianPolicyForm providers={providers} />
    </ContentLayout>
  );
}
