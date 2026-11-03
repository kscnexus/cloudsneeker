import { Sparkles } from "lucide-react";

import { getProviders } from "@/actions/providers/providers";
import { BRAND } from "@/cloudsneeker/brand";
import { CustodianPolicyGenerator } from "@/cloudsneeker/components/custodian-policy-generator";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { isLibraryProvider } from "@/cloudsneeker/lib/custodian-library";
import { ContentLayout } from "@/components/shadcn/content-layout";

// Drafting calls the tenant's LLM and validates the result, which can take
// longer than the default function limit.
export const maxDuration = 60;

export default async function GeneratePolicyPage() {
  const providersResponse = await getProviders({
    pageSize: 100,
    filters: { "filter[provider__in]": "aws,azure,gcp" },
  });

  const providers = (providersResponse?.data ?? []).flatMap((provider) => {
    const providerType = provider.attributes.provider;
    if (!isLibraryProvider(providerType)) return [];
    return [
      {
        id: provider.id,
        providerType,
        label:
          provider.attributes.alias || provider.attributes.uid || provider.id,
      },
    ];
  });

  return (
    <ContentLayout title="Generate a policy" icon={<Sparkles />}>
      <PageHeader
        description={`Describe a rule and ${BRAND.assistantName} drafts a ${BRAND.governanceName} policy. Drafts are validated and shown for review before anything is saved, and policies only run as dry-runs.`}
      />
      <CustodianPolicyGenerator providers={providers} />
    </ContentLayout>
  );
}
