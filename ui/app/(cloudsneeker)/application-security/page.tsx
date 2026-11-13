import { Plus, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import { getAppSecOverview } from "@/cloudsneeker/actions/appsec";
import { BRAND } from "@/cloudsneeker/brand";
import { AppSecOverviewPanel } from "@/cloudsneeker/components/appsec-overview";
import { LoadError } from "@/cloudsneeker/components/appsec-ui";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { TargetReportDownloadButton } from "@/cloudsneeker/components/target-report-download-button";
import { APPSEC_SEGMENT, attributesOf } from "@/cloudsneeker/lib/appsec";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type { AppSecOverview } from "@/cloudsneeker/types/appsec";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default function ApplicationSecurityOverviewPage() {
  return (
    <ContentLayout title={BRAND.appSecurityName} icon={<ShieldCheck />}>
      <PageHeader
        description="Security posture of your applications: vulnerable dependencies, misconfigurations, secrets, license risk and code weaknesses across repositories, images, archives, SBOMs and clusters."
        actions={
          <>
            <TargetReportDownloadButton label="Download SCA and SAST reports" />
            <Button asChild size="sm" variant="outline">
              <Link href={appSecurityHref(APPSEC_SEGMENT.SCANS)}>Scans</Link>
            </Button>
            <Button asChild size="sm">
              <Link href={appSecurityHref("new")}>
                <Plus aria-hidden="true" />
                New target
              </Link>
            </Button>
          </>
        }
      />
      <Suspense fallback={<Skeleton className="h-96 w-full rounded-xl" />}>
        <SSROverview />
      </Suspense>
    </ContentLayout>
  );
}

const SSROverview = async () => {
  const overview = attributesOf<AppSecOverview>(await getAppSecOverview());
  if (!overview) {
    return (
      <LoadError
        title="Overview"
        what="The overview"
        reloadHref={appSecurityHref()}
      />
    );
  }
  return <AppSecOverviewPanel overview={overview} />;
};
