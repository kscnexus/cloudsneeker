import { Download } from "lucide-react";

import { reportDownloadHref } from "@/cloudsneeker/routes";
import {
  REPORT_FORMAT,
  type ReportFormat,
} from "@/cloudsneeker/types/reports";
import { Button } from "@/components/shadcn";

const FORMAT_LABEL: Record<ReportFormat, string> = {
  [REPORT_FORMAT.PDF]: "PDF",
  [REPORT_FORMAT.XLSX]: "Excel",
  [REPORT_FORMAT.CSV]: "CSV",
  [REPORT_FORMAT.JSON]: "JSON",
};

const DOWNLOAD_ORDER: ReportFormat[] = [
  REPORT_FORMAT.PDF,
  REPORT_FORMAT.XLSX,
  REPORT_FORMAT.CSV,
];

interface ReportDownloadLinksProps {
  runId: string;
  formats: ReportFormat[];
  size?: "sm" | "xs";
}

/** One download button per generated file (JSON stays in-app only). */
export const ReportDownloadLinks = ({
  runId,
  formats,
  size = "xs",
}: ReportDownloadLinksProps) => {
  const available = DOWNLOAD_ORDER.filter((format) => formats.includes(format));
  if (available.length === 0) return null;
  return (
    <>
      {available.map((format) => (
        <Button key={format} asChild variant="outline" size={size}>
          <a
            href={reportDownloadHref(runId, format)}
            download
            aria-label={`Download ${FORMAT_LABEL[format]}`}
          >
            <Download aria-hidden="true" />
            {FORMAT_LABEL[format]}
          </a>
        </Button>
      ))}
    </>
  );
};
