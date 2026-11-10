import { ShieldAlert } from "lucide-react";
import Link from "next/link";

import { listAreaFindings } from "@/cloudsneeker/actions/finding-triage";
import { AppSecurityFindingDetail } from "@/cloudsneeker/components/app-security-finding-detail";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { AREA_CONFIG } from "@/cloudsneeker/lib/area-findings";
import {
  isListResponse,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import {
  type AreaFindingResource,
  FINDING_AREA,
} from "@/cloudsneeker/types/area-findings";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

interface FindingPageProps {
  params: Promise<{ findingId: string }>;
}

export default async function AppSecurityFindingPage({
  params,
}: FindingPageProps) {
  const { findingId } = await params;
  const uid = decodeURIComponent(findingId);
  const config = AREA_CONFIG[FINDING_AREA.APPLICATION_SECURITY];
  const response = await listAreaFindings({
    "filter[area]": FINDING_AREA.APPLICATION_SECURITY,
    "filter[uid]": uid,
    // Resolved and accepted findings stay readable here.
    "filter[muted]": "include",
    "filter[status]": "all",
    "page[size]": "1",
  });
  const finding = isListResponse(response)
    ? responseList<AreaFindingResource>(response)[0]
    : undefined;
  const back = (
    <Button asChild size="sm" variant="outline">
      <Link href={config.findingsHref}>All findings</Link>
    </Button>
  );

  if (!finding) {
    return (
      <ContentLayout title="Finding" icon={<ShieldAlert />}>
        <SectionCard title="Finding">
          <EmptyState
            title={
              isListResponse(response)
                ? "This finding is not in the latest scans"
                : "The finding could not be loaded"
            }
            description={
              isListResponse(response)
                ? "It may have been fixed, or its target was rescanned or removed."
                : "The service did not answer. Reload the page in a moment."
            }
            action={back}
          />
        </SectionCard>
      </ContentLayout>
    );
  }

  return (
    <ContentLayout title={finding.attributes.title} icon={<ShieldAlert />}>
      <PageHeader
        description="What is wrong, where it is, why it matters, how to fix it and how to verify the fix."
        actions={back}
      />
      <AppSecurityFindingDetail finding={finding.attributes} />
    </ContentLayout>
  );
}
