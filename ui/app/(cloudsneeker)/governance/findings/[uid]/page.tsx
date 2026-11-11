import { ShieldAlert } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { auth } from "@/auth.config";
import { listAreaFindings } from "@/cloudsneeker/actions/finding-triage";
import { GovernanceFindingDetail } from "@/cloudsneeker/components/governance-finding-detail";
import { PageHeader } from "@/cloudsneeker/components/page-header";
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

interface PageProps {
  params: Promise<{ uid: string }>;
}

export default async function GovernanceFindingPage({ params }: PageProps) {
  const { uid: rawUid } = await params;
  const uid = decodeURIComponent(rawUid);
  const [response, session] = await Promise.all([
    listAreaFindings({
      "filter[area]": FINDING_AREA.GOVERNANCE,
      "filter[uid]": uid,
    }),
    auth(),
  ]);
  const finding = isListResponse(response)
    ? responseList<AreaFindingResource>(response)[0]?.attributes
    : undefined;
  if (!finding) notFound();

  return (
    <ContentLayout title={finding.check_id || "Finding"} icon={<ShieldAlert />}>
      <PageHeader
        actions={
          <Button asChild variant="ghost" size="sm">
            <Link href={AREA_CONFIG[FINDING_AREA.GOVERNANCE].findingsHref}>
              Back to governance findings
            </Link>
          </Button>
        }
      />
      <GovernanceFindingDetail
        finding={finding}
        canTriage={Boolean(session?.user?.permissions?.manage_scans)}
      />
    </ContentLayout>
  );
}
