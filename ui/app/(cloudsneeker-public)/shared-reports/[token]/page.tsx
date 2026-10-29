import type { Metadata } from "next";

import { getSharedReport } from "@/cloudsneeker/actions/shared-reports";
import { ReportPrintButton } from "@/cloudsneeker/components/report-print-button";
import { ReportView } from "@/cloudsneeker/components/report-view";
import {
  SharedReportHeader,
  SharedReportState,
} from "@/cloudsneeker/components/shared-report-state";
import { SHARED_REPORT_STATUS } from "@/cloudsneeker/lib/shared-report";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Shared report",
  robots: { index: false, follow: false },
  referrer: "no-referrer",
};

interface SharedReportPageProps {
  params: Promise<{ token: string }>;
}

export default async function SharedReportPage({
  params,
}: SharedReportPageProps) {
  const { token } = await params;
  const result = await getSharedReport(token);

  if (result.status !== SHARED_REPORT_STATUS.OK) {
    return <SharedReportState status={result.status} />;
  }

  return (
    <main className="mx-auto flex w-full max-w-6xl flex-col gap-6 px-4 py-8 print:max-w-none print:p-0">
      <ReportView
        report={result.report}
        brandHeader={
          <SharedReportHeader>
            <span className="print:hidden">
              <ReportPrintButton />
            </span>
          </SharedReportHeader>
        }
      />
    </main>
  );
}
