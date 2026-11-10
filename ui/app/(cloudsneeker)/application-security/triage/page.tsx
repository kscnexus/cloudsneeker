import { Suspense } from "react";

import { AppSecurityRemediationQueue } from "@/cloudsneeker/components/app-security-remediation-queue";
import { AreaTriageView } from "@/cloudsneeker/components/area-triage-view";
import { FINDING_AREA } from "@/cloudsneeker/types/area-findings";
import { Skeleton } from "@/components/shadcn";
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
      title="Remediation"
      searchParams={await searchParams}
      intro={
        <Suspense fallback={<Skeleton className="h-32 w-full rounded-xl" />}>
          <AppSecurityRemediationQueue />
        </Suspense>
      }
    />
  );
}
