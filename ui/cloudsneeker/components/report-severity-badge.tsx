import { severityLabel } from "@/cloudsneeker/lib/report-view";
import { cn } from "@/lib/utils";

const SEVERITY_CLASS: Record<string, string> = {
  critical: "bg-bg-data-critical text-white",
  high: "bg-bg-data-high text-black",
  medium: "bg-bg-data-medium text-black",
  low: "bg-bg-data-low text-black",
  informational: "bg-bg-data-info text-white",
};

export const ReportSeverityBadge = ({ severity }: { severity: string }) => (
  <span
    className={cn(
      "inline-flex rounded-full px-2 py-0.5 text-xs font-semibold whitespace-nowrap print:border print:border-current",
      SEVERITY_CLASS[severity.toLowerCase()] ??
        "bg-bg-neutral-tertiary text-text-neutral-primary",
    )}
  >
    {severityLabel(severity)}
  </span>
);
