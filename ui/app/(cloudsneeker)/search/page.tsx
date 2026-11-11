import { Search } from "lucide-react";

import { searchEverything } from "@/cloudsneeker/actions/global-search";
import { GlobalSearchBox } from "@/cloudsneeker/components/global-search-box";
import { GlobalSearchResults } from "@/cloudsneeker/components/global-search-results";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import {
  SEARCH_MIN_LENGTH,
  searchQueryOf,
  toSearchGroups,
} from "@/cloudsneeker/lib/global-search";
import { ContentLayout } from "@/components/shadcn/content-layout";

interface PageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function SearchPage({ searchParams }: PageProps) {
  const query = searchQueryOf(await searchParams);
  const response = query ? await searchEverything(query) : null;
  const loadError =
    response && typeof response === "object" && "error" in response
      ? String((response as { error: unknown }).error)
      : null;

  return (
    <ContentLayout title="Search" icon={<Search />}>
      <PageHeader description="One search across Cloud Security, Application Security and Cloud Governance." />
      <div className="mb-6 max-w-2xl">
        <GlobalSearchBox defaultValue={query} autoFocus={!query} />
      </div>
      {query ? (
        <GlobalSearchResults
          query={query}
          groups={loadError ? [] : toSearchGroups(response, query)}
          loadError={loadError}
        />
      ) : (
        <p className="text-text-neutral-secondary text-sm">
          Type at least {SEARCH_MIN_LENGTH} characters.
        </p>
      )}
    </ContentLayout>
  );
}
