import { ScanSearch } from "lucide-react";

import { getProviders } from "@/actions/providers/providers";
import { listAppSecApplications } from "@/cloudsneeker/actions/appsec";
import { BRAND } from "@/cloudsneeker/brand";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { TrivyTargetForm } from "@/cloudsneeker/components/trivy-target-form";
import { APP_SECURITY_PROVIDER_PARAM } from "@/cloudsneeker/lib/app-security-dashboard";
import { loadProfileOptions } from "@/cloudsneeker/lib/appsec-server";
import { responseList } from "@/cloudsneeker/lib/findings-links";
import { labelForProviderType } from "@/cloudsneeker/lib/trivy-modes";
import type {
  AppSecApplicationAttributes,
  AppSecResource,
} from "@/cloudsneeker/types/appsec";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";

interface NewTrivyTargetPageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function NewTrivyTargetPage({
  searchParams,
}: NewTrivyTargetPageProps) {
  const requestedProvider = (await searchParams)[APP_SECURITY_PROVIDER_PARAM];
  const [providersResponse, profiles, applicationsResponse] = await Promise.all(
    [
      getProviders({ pageSize: 100 }),
      loadProfileOptions(),
      listAppSecApplications({ "page[size]": "100" }),
    ],
  );
  const applications = responseList<
    AppSecResource<AppSecApplicationAttributes>
  >(applicationsResponse).map((application) => ({
    value: application.id,
    label: application.attributes.name,
  }));
  const providers = (providersResponse?.data ?? []).map((provider) => ({
    id: provider.id,
    providerType: provider.attributes.provider,
    label: [
      labelForProviderType(provider.attributes.provider),
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
      <TrivyTargetForm
        providers={providers}
        profiles={profiles.map((item) => ({
          value: item.ref,
          label: item.name,
        }))}
        applications={applications}
        defaultProviderId={
          typeof requestedProvider === "string" ? requestedProvider : undefined
        }
      />
    </ContentLayout>
  );
}
