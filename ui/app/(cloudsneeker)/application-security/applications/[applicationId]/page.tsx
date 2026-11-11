import { Boxes } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { getAppSecApplication } from "@/cloudsneeker/actions/appsec";
import { AppSecApplicationForm } from "@/cloudsneeker/components/appsec-application-form";
import {
  ROW_LINK_CLASS,
  TABLE_CLASS,
  TABLE_WRAPPER_CLASS,
  TD_CLASS,
  TD_PRIMARY_CLASS,
  TH_CLASS,
} from "@/cloudsneeker/components/appsec-ui";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { StatTile } from "@/cloudsneeker/components/stat-tile";
import {
  APPSEC_SEGMENT,
  appSecFindingsHref,
  attributesOf,
  formatAppSecDate,
} from "@/cloudsneeker/lib/appsec";
import {
  canManageScans,
  loadProfileOptions,
  loadTargetOptions,
} from "@/cloudsneeker/lib/appsec-server";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type { AppSecApplicationAttributes } from "@/cloudsneeker/types/appsec";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";
import { cn } from "@/lib/utils";

interface PageProps {
  params: Promise<{ applicationId: string }>;
}

export default async function AppSecurityApplicationPage({
  params,
}: PageProps) {
  const { applicationId } = await params;
  const [response, canManage] = await Promise.all([
    getAppSecApplication(applicationId),
    canManageScans(),
  ]);
  const application = attributesOf<AppSecApplicationAttributes>(response);
  if (!application) notFound();
  const [targets, profiles] = canManage
    ? await Promise.all([loadTargetOptions(), loadProfileOptions()])
    : [[], []];
  const assets = application.assets ?? [];
  const scoped = (filters: Parameters<typeof appSecFindingsHref>[1]) =>
    appSecFindingsHref(APPSEC_SEGMENT.FINDINGS, {
      application: applicationId,
      ...filters,
    });

  return (
    <ContentLayout title={application.name} icon={<Boxes />}>
      <PageHeader
        description={application.description || undefined}
        meta={[
          { label: "Owner", value: application.owner || "Not set" },
          { label: "Criticality", value: application.criticality },
          { label: "Environment", value: application.environment },
          {
            label: "Internet facing",
            value:
              application.internet_exposed === null
                ? "Not stated"
                : application.internet_exposed
                  ? "Yes"
                  : "No",
          },
          {
            label: "Last scan",
            value: application.last_scan_at
              ? formatAppSecDate(application.last_scan_at)
              : "Never",
          },
        ]}
        actions={
          <Button asChild size="sm" variant="outline">
            <Link href={appSecurityHref(APPSEC_SEGMENT.APPLICATIONS)}>
              All applications
            </Link>
          </Button>
        }
      />
      <div className="flex flex-col gap-6">
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          <StatTile
            label="Active findings"
            value={application.active_findings ?? 0}
            href={scoped({})}
          />
          <StatTile
            label="Urgent priority"
            value={application.urgent ?? 0}
            tone="danger"
            href={scoped({ priorities: ["urgent"] })}
          />
          <StatTile
            label="Critical"
            value={application.critical ?? 0}
            tone="critical"
            href={scoped({ severities: ["critical"] })}
          />
          <StatTile
            label="High"
            value={application.high ?? 0}
            tone="high"
            href={scoped({ severities: ["high"] })}
          />
          <StatTile
            label="Assets with SBOM"
            value={`${application.sbom_targets ?? 0} of ${application.targets ?? 0}`}
            href={`${appSecurityHref(APPSEC_SEGMENT.SBOMS)}?application=${encodeURIComponent(applicationId)}`}
          />
        </div>

        <SectionCard
          title="Assets"
          description="Open an asset for its scans and schedule, or its findings."
        >
          {assets.length === 0 ? (
            <EmptyState
              title="No assets assigned"
              description="Assign targets to this application in the form below."
            />
          ) : (
            <div className={TABLE_WRAPPER_CLASS}>
              <table className={TABLE_CLASS}>
                <thead>
                  <tr>
                    {[
                      "Asset",
                      "Type",
                      "Source",
                      "Schedule",
                      "Active",
                      "Critical",
                      "High",
                    ].map((heading) => (
                      <th key={heading} scope="col" className={TH_CLASS}>
                        {heading}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {assets.map((asset) => (
                    <tr key={asset.id}>
                      <td className={TD_PRIMARY_CLASS}>
                        <Link
                          href={appSecurityHref(asset.id)}
                          className={ROW_LINK_CLASS}
                        >
                          {asset.name}
                        </Link>
                      </td>
                      <td className={TD_CLASS}>
                        {labelForTrivyMode(asset.target_type)}
                      </td>
                      <td
                        className={cn(TD_CLASS, "max-w-xs text-xs break-all")}
                      >
                        {asset.provider_uid}
                      </td>
                      <td className={TD_CLASS}>
                        {asset.schedule_enabled ? "Scheduled" : "On demand"}
                      </td>
                      <td className={cn(TD_CLASS, "tabular-nums")}>
                        <Link
                          className="underline"
                          href={appSecFindingsHref(APPSEC_SEGMENT.FINDINGS, {
                            target: asset.id,
                          })}
                        >
                          {asset.active_findings}
                        </Link>
                      </td>
                      <td className={cn(TD_CLASS, "tabular-nums")}>
                        {asset.critical}
                      </td>
                      <td className={cn(TD_CLASS, "tabular-nums")}>
                        {asset.high}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </SectionCard>

        {canManage ? (
          <AppSecApplicationForm
            applicationId={applicationId}
            initial={application}
            targets={targets}
            profiles={profiles}
          />
        ) : null}
      </div>
    </ContentLayout>
  );
}
