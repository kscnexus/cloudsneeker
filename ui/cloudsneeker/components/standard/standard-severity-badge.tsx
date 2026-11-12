import {
  type Severity,
  SeverityBadge,
  SeverityValues,
} from "@/components/shadcn/table/severity-badge";

const KNOWN: readonly string[] = Object.values(SeverityValues);

/** Severity as the Cloud Security Findings table shows it (colour square and
 * label). Values outside the five levels ("unknown") read neutral. */
export const StandardSeverityBadge = ({ severity }: { severity: string }) => {
  const value = (severity || "").toLowerCase();
  const normalized = value === "info" ? SeverityValues.INFORMATIONAL : value;
  if (KNOWN.includes(normalized)) {
    return <SeverityBadge severity={normalized as Severity} />;
  }
  return (
    <div className="flex items-center gap-1">
      <div className="bg-bg-neutral-tertiary border-border-neutral-secondary size-3 rounded border" />
      <span className="text-text-neutral-secondary text-sm capitalize">
        {value || "Unknown"}
      </span>
    </div>
  );
};
