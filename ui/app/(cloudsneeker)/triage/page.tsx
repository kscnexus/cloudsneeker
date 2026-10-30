import { ClipboardCheck } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { listFindingTriages } from "@/cloudsneeker/actions/finding-triage";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { FindingTriageStatusFilter } from "@/cloudsneeker/components/finding-triage-status-filter";
import { FindingTriageTable } from "@/cloudsneeker/components/finding-triage-table";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  parseTriagePage,
  parseTriageStatus,
  TRIAGE_PAGE_PARAM,
  TRIAGE_STATUS_PARAM,
  triageListSearchParams,
  triagePageHref,
  triageStatusLabel,
} from "@/cloudsneeker/lib/finding-triage";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import type { FindingTriageResource } from "@/cloudsneeker/types/finding-triage";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types";
import type { FindingTriageStatus } from "@/types/findings-triage";

interface TriagePageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function TriagePage({ searchParams }: TriagePageProps) {
  const resolvedSearchParams = await searchParams;
  const status = parseTriageStatus(resolvedSearchParams[TRIAGE_STATUS_PARAM]);
  const page = parseTriagePage(resolvedSearchParams[TRIAGE_PAGE_PARAM]);

  return (
    <ContentLayout title="Triage" icon={<ClipboardCheck />}>
      <PageHeader description="Findings your team has triaged. A status follows the finding across rescans; change it or add notes from the finding row or detail on the Findings page." />
      <Suspense
        key={`${status ?? "all"}-${page}`}
        fallback={<Skeleton className="h-64 w-full rounded-xl" />}
      >
        <SSRTriageList status={status} page={page} />
      </Suspense>
    </ContentLayout>
  );
}

const pagesOf = (response: unknown): number => {
  const pages = (
    response as { meta?: { pagination?: { pages?: unknown } } } | undefined
  )?.meta?.pagination?.pages;
  return typeof pages === "number" && pages > 0 ? pages : 1;
};

const SSRTriageList = async ({
  status,
  page,
}: {
  status: FindingTriageStatus | null;
  page: number;
}) => {
  const response = await listFindingTriages(
    triageListSearchParams({ status, page }),
  );
  const filter = <FindingTriageStatusFilter active={status} />;

  if (!isListResponse(response)) {
    // A failed request must not read as "nothing triaged yet".
    return (
      <SectionCard title="Triaged findings" actions={filter}>
        <EmptyState
          title="Triage could not be loaded"
          description="The service did not answer. Reload the page in a moment."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={triagePageHref(status, page)}>Reload</Link>
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
          description="Set a triage status on a finding from the Findings page to track it here."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href="/findings">Go to Findings</Link>
            </Button>
          }
        />
      ) : (
        <FindingTriageTable triages={triages} />
      )}
      {pages > 1 ? (
        <div className="flex items-center justify-end gap-2 text-sm">
          <span className="text-text-neutral-tertiary">
            Page {page} of {pages}
          </span>
          {page > 1 ? (
            <Button asChild size="xs" variant="outline">
              <Link href={triagePageHref(status, page - 1)}>Previous</Link>
            </Button>
          ) : null}
          {page < pages ? (
            <Button asChild size="xs" variant="outline">
              <Link href={triagePageHref(status, page + 1)}>Next</Link>
            </Button>
          ) : null}
        </div>
      ) : null}
    </SectionCard>
  );
};
