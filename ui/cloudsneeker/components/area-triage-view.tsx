import { ClipboardCheck } from "lucide-react";
import Link from "next/link";
import { type ReactNode, Suspense } from "react";

import { listFindingTriages } from "@/cloudsneeker/actions/finding-triage";
import {
  AREA_CONFIG,
  areaTriagePageHref,
  areaTriageSearchParams,
} from "@/cloudsneeker/lib/area-findings";
import {
  parseTriagePage,
  parseTriageStatus,
  TRIAGE_PAGE_PARAM,
  TRIAGE_STATUS_PARAM,
  triageStatusLabel,
} from "@/cloudsneeker/lib/finding-triage";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import {
  FINDING_AREA,
  type FindingArea,
} from "@/cloudsneeker/types/area-findings";
import type { FindingTriageResource } from "@/cloudsneeker/types/finding-triage";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";
import type { FindingTriageStatus } from "@/types/findings-triage";

import { EmptyState } from "./empty-state";
import { FindingTriageStatusFilter } from "./finding-triage-status-filter";
import { FindingTriageTable } from "./finding-triage-table";
import { PageHeader } from "./page-header";
import { PageNav } from "./page-nav";
import { SectionCard } from "./section-card";

interface AreaTriageViewProps {
  area: FindingArea;
  searchParams: SearchParamsProps;
  /** Page title instead of "<Area> triage". */
  title?: string;
  /** Shown above the triage list (for example a remediation summary). */
  intro?: ReactNode;
}

export const pagesOf = (response: unknown): number => {
  const pages = (
    response as { meta?: { pagination?: { pages?: unknown } } } | undefined
  )?.meta?.pagination?.pages;
  return typeof pages === "number" && pages > 0 ? pages : 1;
};

const DESCRIPTION: Record<FindingArea, string> = {
  [FINDING_AREA.CLOUD]:
    "Cloud findings your team has triaged. A status follows the finding across rescans; change it or add notes from the finding row or detail on the Findings page.",
  [FINDING_AREA.APPLICATION_SECURITY]:
    "Code, dependency, image and secret findings your team has triaged. A status follows the finding across rescans of the target.",
  [FINDING_AREA.GOVERNANCE]:
    "Policy matches your team has triaged. A status follows the resource across dry runs of the policy.",
};

/** One area's Triage page: triaged findings by status. */
export const AreaTriageView = ({
  area,
  searchParams,
  title: titleOverride,
  intro,
}: AreaTriageViewProps) => {
  const status = parseTriageStatus(searchParams[TRIAGE_STATUS_PARAM]);
  const page = parseTriagePage(searchParams[TRIAGE_PAGE_PARAM]);
  const title =
    titleOverride ??
    (area === FINDING_AREA.CLOUD
      ? "Triage"
      : `${AREA_CONFIG[area].name} triage`);

  return (
    <ContentLayout title={title} icon={<ClipboardCheck />}>
      <PageHeader description={DESCRIPTION[area]} />
      {intro ? <div className="mb-6">{intro}</div> : null}
      <Suspense
        key={`${area}-${status ?? "all"}-${page}`}
        fallback={<Skeleton className="h-64 w-full rounded-xl" />}
      >
        <SSRAreaTriageList area={area} status={status} page={page} />
      </Suspense>
    </ContentLayout>
  );
};

const SSRAreaTriageList = async ({
  area,
  status,
  page,
}: {
  area: FindingArea;
  status: FindingTriageStatus | null;
  page: number;
}) => {
  const config = AREA_CONFIG[area];
  const response = await listFindingTriages(
    areaTriageSearchParams(area, status, page),
  );
  const filter = <FindingTriageStatusFilter active={status} area={area} />;

  if (!isListResponse(response)) {
    // A failed request must not read as "nothing triaged yet".
    return (
      <SectionCard title="Triaged findings" actions={filter}>
        <EmptyState
          title="Triage could not be loaded"
          description="The service did not answer. Reload the page in a moment."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={areaTriagePageHref(area, status, page)}>Reload</Link>
            </Button>
          }
        />
      </SectionCard>
    );
  }

  const triages = responseList<FindingTriageResource>(response);
  const total = responseCount(response) ?? triages.length;
  const pages = pagesOf(response);

  return (
    <SectionCard
      title="Triaged findings"
      description={
        status
          ? `${total} finding(s) marked ${triageStatusLabel(status)}.`
          : `${total} triaged finding(s).`
      }
      actions={filter}
    >
      {triages.length === 0 ? (
        <EmptyState
          title={
            status ? "No findings with this status" : "Nothing triaged yet"
          }
          description={`Set a triage status on any ${config.name} finding to track it here.`}
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={config.findingsHref}>Go to findings</Link>
            </Button>
          }
        />
      ) : (
        <FindingTriageTable triages={triages} area={area} />
      )}
      <PageNav
        page={page}
        pages={pages}
        hrefFor={(target) => areaTriagePageHref(area, status, target)}
      />
    </SectionCard>
  );
};
