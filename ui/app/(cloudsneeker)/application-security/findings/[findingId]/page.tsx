import { ShieldAlert } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { auth } from "@/auth.config";
import { getAppSecFinding } from "@/cloudsneeker/actions/appsec";
import { AppSecFindingDetail } from "@/cloudsneeker/components/appsec-finding-detail";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import {
  appSecFindingsHref,
  attributesOf,
  workspaceForCategory,
} from "@/cloudsneeker/lib/appsec";
import type { AppSecFindingDetailAttributes } from "@/cloudsneeker/types/appsec";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

interface PageProps {
  params: Promise<{ findingId: string }>;
}

export default async function AppSecurityFindingPage({ params }: PageProps) {
  const { findingId } = await params;
  const [response, session] = await Promise.all([
    getAppSecFinding(findingId),
    auth(),
  ]);
  const finding = attributesOf<AppSecFindingDetailAttributes>(response);
  if (!finding) notFound();
  const workspace = workspaceForCategory(finding.category);

  return (
    <ContentLayout title={finding.rule_id || "Finding"} icon={<ShieldAlert />}>
      <PageHeader
        actions={
          <Button asChild variant="ghost" size="sm">
            <Link href={appSecFindingsHref(workspace.segment)}>
              Back to {workspace.title.toLowerCase()}
            </Link>
          </Button>
        }
      />
      <AppSecFindingDetail
        findingId={findingId}
        finding={finding}
        canTriage={Boolean(session?.user?.permissions?.manage_scans)}
      />
    </ContentLayout>
  );
}
