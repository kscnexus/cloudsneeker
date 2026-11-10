import {
  ArrowUpCircle,
  CircleCheck,
  CircleDashed,
  ExternalLink,
} from "lucide-react";

import type { AreaFindingAttributes } from "@/cloudsneeker/types/area-findings";
import { cn } from "@/lib/utils";

type FixFields = Pick<
  AreaFindingAttributes,
  | "fix_available"
  | "fix_summary"
  | "installed_version"
  | "fixed_version"
  | "fix_references"
  | "remediation"
>;

const pillClass =
  "inline-flex max-w-[14rem] items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium";

/** Fix state in the findings table: "Upgrade to x", "Fix available", or "No fix yet". */
export const AreaFindingFixCell = ({ finding }: { finding: FixFields }) => {
  if (finding.fix_available && finding.fixed_version) {
    return (
      <span
        className={cn(
          pillClass,
          "border-bg-pass-primary bg-bg-pass-secondary text-text-success-primary",
        )}
        title={finding.fix_summary || undefined}
      >
        <ArrowUpCircle aria-hidden="true" className="size-3.5 shrink-0" />
        <span className="truncate">Upgrade to {finding.fixed_version}</span>
      </span>
    );
  }
  if (finding.fix_available) {
    return (
      <span
        className={cn(
          pillClass,
          "border-bg-pass-primary bg-bg-pass-secondary text-text-success-primary",
        )}
        title={finding.fix_summary || undefined}
      >
        <CircleCheck aria-hidden="true" className="size-3.5 shrink-0" />
        Fix available
      </span>
    );
  }
  if (finding.fix_summary) {
    return (
      <span
        className={cn(
          pillClass,
          "border-border-neutral-secondary text-text-warning-primary",
        )}
        title={finding.fix_summary}
      >
        <CircleDashed aria-hidden="true" className="size-3.5 shrink-0" />
        No fix yet
      </span>
    );
  }
  return <span className="text-text-neutral-tertiary text-xs">—</span>;
};

const hostOf = (url: string): string => {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return url;
  }
};

/** "How to fix" block in an expanded finding row. */
export const AreaFindingFixDetails = ({ finding }: { finding: FixFields }) => {
  const summary = finding.fix_summary || finding.remediation;
  if (!summary && !finding.fix_references?.length) return null;
  return (
    <div
      className={cn(
        "rounded-lg border p-3 sm:col-span-2",
        finding.fix_available
          ? "border-bg-pass-primary bg-bg-pass-secondary"
          : "border-border-neutral-secondary",
      )}
    >
      <dt className="text-text-neutral-primary flex items-center gap-1.5 font-semibold">
        {finding.fix_available ? (
          <CircleCheck
            aria-hidden="true"
            className="text-text-success-primary size-4"
          />
        ) : (
          <CircleDashed
            aria-hidden="true"
            className="text-text-warning-primary size-4"
          />
        )}
        How to fix
      </dt>
      <dd className="mt-1 flex flex-col gap-2">
        {summary ? (
          <p className="text-text-neutral-primary whitespace-pre-line">
            {summary}
          </p>
        ) : null}
        {finding.installed_version || finding.fixed_version ? (
          <p className="text-text-neutral-secondary font-mono">
            {finding.installed_version || "?"}
            {" → "}
            <span
              className={
                finding.fixed_version
                  ? "text-text-success-primary font-semibold"
                  : undefined
              }
            >
              {finding.fixed_version || "no fixed version yet"}
            </span>
          </p>
        ) : null}
        {finding.fix_references?.length ? (
          <ul className="flex flex-wrap gap-x-4 gap-y-1">
            {finding.fix_references.map((url) => (
              <li key={url}>
                <a
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-button-primary inline-flex items-center gap-1 hover:underline"
                >
                  {hostOf(url)}
                  <ExternalLink aria-hidden="true" className="size-3" />
                </a>
              </li>
            ))}
          </ul>
        ) : null}
      </dd>
    </div>
  );
};
