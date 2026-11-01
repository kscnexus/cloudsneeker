import { AreaTriageView } from "@/cloudsneeker/components/area-triage-view";
import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";
import type { SearchParamsProps } from "@/types";

interface PageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function GovernanceTriagePage({
  searchParams,
}: PageProps) {
  return (
    <AreaTriageView
      area={FINDING_AREA.GOVERNANCE}
      searchParams={await searchParams}
    />
  );
}
