import { ShieldPlus } from "lucide-react";

import { getProviders } from "@/actions/providers/providers";
import { CustodianPolicyForm } from "@/cloudsneeker/components/custodian-policy-form";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function NewCustodianPolicyPage() {
  const providersResponse = await getProviders({
    pageSize: 100,
    filters: { "filter[provider]": "aws" },
  });

  const providers = (providersResponse?.data ?? []).map((provider) => ({
    id: provider.id,
    label:
      provider.attributes.alias ||
      provider.attributes.uid ||
      provider.id,
  }));

  return (
    <ContentLayout title="New Custodian policy" icon={<ShieldPlus />}>
      <CustodianPolicyForm providers={providers} />
    </ContentLayout>
  );
}
