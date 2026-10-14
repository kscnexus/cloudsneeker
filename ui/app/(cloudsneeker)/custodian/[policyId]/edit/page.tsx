import { Shield } from "lucide-react";
import { notFound } from "next/navigation";

import { getProviders } from "@/actions/providers/providers";
import { getCustodianPolicy } from "@/cloudsneeker/actions/custodian";
import { CustodianPolicyForm } from "@/cloudsneeker/components/custodian-policy-form";
import { CUSTODIAN_PROVIDER_FILTER } from "@/cloudsneeker/lib/custodian-providers";
import { presetFromCron } from "@/cloudsneeker/lib/custodian-schedule";
import type { CustodianPolicyResource } from "@/cloudsneeker/types/custodian";
import { ContentLayout } from "@/components/shadcn/content-layout";

interface EditCustodianPolicyPageProps {
  params: Promise<{ policyId: string }>;
}

export default async function EditCustodianPolicyPage({
  params,
}: EditCustodianPolicyPageProps) {
  const { policyId } = await params;
  const policyResponse = await getCustodianPolicy(policyId);

  if (
    !policyResponse ||
    ("error" in policyResponse && policyResponse.error) ||
    !policyResponse.data ||
    Array.isArray(policyResponse.data)
  ) {
    notFound();
  }

  const policy = policyResponse.data as CustodianPolicyResource;
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

  const schedule = presetFromCron(
    Boolean(policy.attributes.schedule_enabled),
    policy.attributes.schedule_cron ?? "",
  );

  return (
    <ContentLayout title={`Edit ${policy.attributes.name}`} icon={<Shield />}>
      <CustodianPolicyForm
        policyId={policyId}
        providers={providers}
        initialValues={{
          name: policy.attributes.name,
          description: policy.attributes.description ?? "",
          providerId: policy.attributes.provider_id,
          policyYaml: policy.attributes.policy_yaml,
          schedulePreset: schedule.preset,
          scheduleHour: schedule.hour,
          scheduleWeekday: schedule.weekday,
          scheduleTimezone: policy.attributes.schedule_timezone ?? "UTC",
          scheduleCron: policy.attributes.schedule_cron ?? "",
        }}
      />
    </ContentLayout>
  );
}
