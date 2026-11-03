import { LibraryBig } from "lucide-react";

import { getProviders } from "@/actions/providers/providers";
import { listCustodianLibrary } from "@/cloudsneeker/actions/custodian-library";
import { BRAND } from "@/cloudsneeker/brand";
import { CustodianLibraryBrowser } from "@/cloudsneeker/components/custodian-library-browser";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import {
  LIBRARY_PROVIDER_LABEL,
  libraryProviderFromParam,
} from "@/cloudsneeker/lib/custodian-library";
import type { LibraryListResponse } from "@/cloudsneeker/types/custodian-library";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";

interface PolicyLibraryPageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function PolicyLibraryPage({
  searchParams,
}: PolicyLibraryPageProps) {
  const resolved = await searchParams;
  const providerType = libraryProviderFromParam(resolved.provider);

  const [libraryResponse, providersResponse] = await Promise.all([
    listCustodianLibrary({ providerType }),
    getProviders({
      pageSize: 100,
      filters: { "filter[provider__in]": providerType },
    }),
  ]);

  const library =
    libraryResponse && !("error" in libraryResponse)
      ? (libraryResponse as LibraryListResponse)
      : null;

  const providers = (providersResponse?.data ?? []).map((provider) => ({
    id: provider.id,
    label: provider.attributes.alias || provider.attributes.uid || provider.id,
  }));

  return (
    <ContentLayout title="Policy library" icon={<LibraryBig />}>
      <PageHeader
        description={`Ready-made ${BRAND.governanceName} policies for ${LIBRARY_PROVIDER_LABEL[providerType]}, grouped by category with framework tags. Every policy runs as a dry-run and only reports what it finds.`}
      />
      {library ? (
        <CustodianLibraryBrowser
          key={providerType}
          providerType={providerType}
          policies={library.data.map((item) => item.attributes)}
          categories={library.meta.categories}
          coverage={library.meta.coverage}
          providers={providers}
        />
      ) : (
        <EmptyState
          icon={<LibraryBig />}
          title="Unable to load the policy library"
          description={
            libraryResponse && "error" in libraryResponse
              ? String(libraryResponse.error)
              : "Try again in a moment."
          }
        />
      )}
    </ContentLayout>
  );
}
