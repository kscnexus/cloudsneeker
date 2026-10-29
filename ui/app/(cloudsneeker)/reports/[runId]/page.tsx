import { FileBarChart } from "lucide-react";
import Link from "next/link";
import { notFound } from "next/navigation";

import { auth } from "@/auth.config";
import {
  getReportRun,
  getReportRunData,
} from "@/cloudsneeker/actions/reports";
import { ReportDownloadLinks } from "@/cloudsneeker/components/report-download-links";
import { ReportPrintButton } from "@/cloudsneeker/components/report-print-button";
import { ReportShareDialog } from "@/cloudsneeker/components/report-share-dialog";
import { ReportView } from "@/cloudsneeker/components/report-view";
import { reportTitle } from "@/cloudsneeker/lib/report-catalog";
import {
  isReportRunActive,
  reportStatusLabel,
} from "@/cloudsneeker/lib/report-view";
import { reportsHref } from "@/cloudsneeker/routes";
import {
  REPORT_RUN_STATUS,
  type ReportPayload,
  type ReportRunResource,
} from "@/cloudsneeker/types/reports";
import { AutoRefresh } from "@/components/scans/auto-refresh";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

interface ReportRunPageProps {
  params: Promise<{ runId: string }>;
}

export default async function ReportRunPage({ params }: ReportRunPageProps) {
  const { runId } = await params;
  const runResponse = await getReportRun(runId);
  const run = runResponse?.data as ReportRunResource | undefined;
  // Error results carry no `data`.
  if (!run || Array.isArray(run)) notFound();

  const attributes = run.attributes;
  const name = reportTitle(attributes.report_type, attributes.report_name);

  if (attributes.status !== REPORT_RUN_STATUS.COMPLETED) {
    const active = isReportRunActive(attributes.status);
    return (
      <ContentLayout title={name} icon={<FileBarChart />}>
        <AutoRefresh hasExecutingScan={active} />
        <div className="border-border-neutral-secondary flex flex-col gap-3 rounded-xl border p-6">
          <p className="text-text-neutral-primary font-medium">
            {reportStatusLabel(attributes.status)}
          </p>
          <p className="text-text-neutral-secondary text-sm">
            {active
              ? "This report is being prepared. The page refreshes when it is ready."
              : attributes.error || "This report could not be generated."}
          </p>
          <div>
            <Button asChild variant="outline" size="sm">
              <Link href={reportsHref()}>Back to reports</Link>
            </Button>
          </div>
        </div>
      </ContentLayout>
    );
  }

  const [session, dataResponse] = await Promise.all([
    auth(),
    getReportRunData(runId),
  ]);
  const report = dataResponse?.data?.attributes as ReportPayload | undefined;
  if (!report) notFound();
  const canShare = Boolean(session?.user?.permissions?.manage_scans);

  return (
    <ContentLayout title={name} icon={<FileBarChart />}>
      <ReportView
        report={report}
        actions={
          <>
            <ReportDownloadLinks
              runId={run.id}
              formats={attributes.available_formats ?? []}
              size="sm"
            />
            {canShare ? (
              <ReportShareDialog runId={run.id} reportName={name} />
            ) : null}
            <ReportPrintButton />
          </>
        }
      />
    </ContentLayout>
  );
}
