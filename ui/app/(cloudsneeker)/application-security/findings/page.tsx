import { notFound } from "next/navigation";

import { AppSecFindingsWorkspace } from "@/cloudsneeker/components/appsec-findings-workspace";
import { APPSEC_SEGMENT, workspaceForSegment } from "@/cloudsneeker/lib/appsec";
import type { SearchParamsProps } from "@/types";

interface PageProps {
  searchParams: Promise<SearchParamsProps>;
}

export default async function AppSecurityFindingsPage({
  searchParams,
}: PageProps) {
  const workspace = workspaceForSegment(APPSEC_SEGMENT.FINDINGS);
  if (!workspace) notFound();
  return (
    <AppSecFindingsWorkspace
      workspace={workspace}
      searchParams={await searchParams}
    />
  );
}
