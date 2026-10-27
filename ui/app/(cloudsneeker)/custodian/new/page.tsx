import { ShieldPlus } from "lucide-react";

import { getProviders } from "@/actions/providers/providers";
import { CustodianPolicyForm } from "@/cloudsneeker/components/custodian-policy-form";
import { CUSTODIAN_PROVIDER_FILTER } from "@/cloudsneeker/lib/custodian-providers";
import { CUSTODIAN_SCHEDULE_PRESET } from "@/cloudsneeker/lib/custodian-schedule";
import { CUSTODIAN_TEMPLATES } from "@/cloudsneeker/lib/custodian-templates";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";

interface NewCustodianPolicyPageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function NewCustodianPolicyPage({
  searchParams,
}: NewCustodianPolicyPageProps) {
  const resolved = await searchParams;
  const templateId =
    typeof resolved.template === "string" ? resolved.template : undefined;
  const template = CUSTODIAN_TEMPLATES.find((item) => item.id === templateId);

  const providersResponse = await getProviders({
    pageSize: 100,
    filters: { ...CUSTODIAN_PROVIDER_FILTER },
  });

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

  const preferredProviders = template
    ? [
        ...providers.filter((provider) =>
          template.providerTypes.includes(provider.providerType),
        ),
        ...providers.filter(
          (provider) =>
            !template.providerTypes.includes(provider.providerType),
        ),
      ]
    : providers;

  return (
    <ContentLayout title="New Custodian policy" icon={<ShieldPlus />}>
      <CustodianPolicyForm
        providers={preferredProviders}
        initialValues={
          template
            ? {
                name: template.name.slice(0, 100),
                description: template.description,
                providerId: preferredProviders[0]?.id ?? "",
                policyYaml: template.policyYaml,
                schedulePreset: CUSTODIAN_SCHEDULE_PRESET.DISABLED,
                scheduleHour: 9,
                scheduleWeekday: 1,
                scheduleTimezone: "UTC",
                scheduleCron: "",
                regionsOverride: "",
              }
            : undefined
        }
      />
    </ContentLayout>
  );
}
