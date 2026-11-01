import { AreaTriageView } from "@/cloudsneeker/components/area-triage-view";
import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";
import type { SearchParamsProps } from "@/types";

interface PageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function AppSecurityTriagePage({
  searchParams,
}: PageProps) {
  return (
    <AreaTriageView
      area={FINDING_AREA.APPLICATION_SECURITY}
      searchParams={await searchParams}
    />
  );
}
