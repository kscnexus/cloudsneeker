import { AreaFindingsView } from "@/cloudsneeker/components/area-findings-view";
import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";
import type { SearchParamsProps } from "@/types";

interface PageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function GovernanceFindingsPage({
  searchParams,
}: PageProps) {
  return (
    <AreaFindingsView
      area={FINDING_AREA.GOVERNANCE}
      searchParams={await searchParams}
    />
  );
}
