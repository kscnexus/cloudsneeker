import { TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";

import { BRAND } from "@/cloudsneeker/brand";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  type ContentVersionsAttributes,
  VULN_DB_STATUS,
  type VulnerabilityDatabaseVersion,
} from "@/cloudsneeker/types/content-versions";
import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";

const NOT_AVAILABLE = "Not available";

const STATUS_LABEL: Record<VulnerabilityDatabaseVersion["status"], string> = {
  [VULN_DB_STATUS.FRESH]: "Current",
  [VULN_DB_STATUS.STALE]: "Out of date",
  [VULN_DB_STATUS.MISSING]: "Not downloaded yet",
  [VULN_DB_STATUS.NOT_CONFIGURED]: "Downloaded by each scan",
};

/** `2026-11-04 06:00 UTC`; the same on the server and in the browser. */
export const formatUtc = (value: string | null): string => {
  if (!value) return NOT_AVAILABLE;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return NOT_AVAILABLE;
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
};

export const formatAge = (hours: number | null): string => {
  if (hours === null) return NOT_AVAILABLE;
  if (hours < 1) return "Less than an hour";
  if (hours < 48) return `${Math.round(hours)} hours`;
  return `${Math.round(hours / 24)} days`;
};

const staleWarning = (db: VulnerabilityDatabaseVersion): string | null => {
  if (db.status === VULN_DB_STATUS.STALE) {
    return `The vulnerability database was last refreshed ${formatAge(db.age_hours).toLowerCase()} ago, more than the ${db.max_age_hours}-hour limit. ${BRAND.appSecurityName} scans download their own copy until the next refresh succeeds.`;
  }
  if (db.status === VULN_DB_STATUS.MISSING) {
    return `The shared vulnerability database has not been downloaded yet. ${BRAND.appSecurityName} scans download their own copy until the first refresh succeeds.`;
  }
  return null;
};

interface VersionRowProps {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
}

const VersionRow = ({ label, value, hint }: VersionRowProps) => (
  <div className="border-border-neutral-secondary grid gap-1 border-b pb-3 last:border-b-0 last:pb-0 sm:grid-cols-[14rem_1fr] sm:gap-4">
    <dt className="text-text-neutral-secondary text-sm font-medium">{label}</dt>
    <dd className="flex min-w-0 flex-col gap-0.5">
      <span className="text-text-neutral-primary text-sm break-words tabular-nums">
        {value}
      </span>
      {hint ? (
        <span className="text-text-neutral-tertiary text-xs">{hint}</span>
      ) : null}
    </dd>
  </div>
);

interface ContentVersionsPanelProps {
  versions: ContentVersionsAttributes;
}

export const ContentVersionsPanel = ({
  versions,
}: ContentVersionsPanelProps) => {
  const db = versions.vulnerability_database;
  const warning = staleWarning(db);
  const posture = versions.cloud_security;
  const rules = versions.code_analysis_rules;

  return (
    <div className="flex flex-col gap-6">
      {warning ? (
        <Alert variant="warning">
          <TriangleAlert />
          <AlertTitle>Vulnerability database is out of date</AlertTitle>
          <AlertDescription>{warning}</AlertDescription>
        </Alert>
      ) : null}

      <SectionCard
        title="Detection content"
        description="The checks, rules and vulnerability data scans use right now."
      >
        <dl className="flex flex-col gap-3">
          <VersionRow
            label={`${BRAND.cloudSecurityName} content`}
            value={`Release ${posture.version}`}
            hint={`${posture.checks.toLocaleString("en-US")} checks, ${posture.frameworks.toLocaleString("en-US")} compliance frameworks`}
          />
          <VersionRow
            label="Vulnerability database"
            value={STATUS_LABEL[db.status]}
            hint={
              db.refreshed_at
                ? `Refreshed ${formatUtc(db.refreshed_at)} (${formatAge(db.age_hours).toLowerCase()} ago). Published ${formatUtc(db.published_at)}. Refreshed every 6 hours.`
                : undefined
            }
          />
          <VersionRow
            label="Code analysis rules"
            value={rules.version ? `Release ${rules.version}` : NOT_AVAILABLE}
            hint={
              rules.rules !== null
                ? `${rules.rules.toLocaleString("en-US")} rule files`
                : undefined
            }
          />
        </dl>
      </SectionCard>

      <SectionCard
        title="Engines"
        description={
          versions.release
            ? `Bundled with platform release ${versions.release}.`
            : "Bundled with this platform release."
        }
      >
        <dl className="flex flex-col gap-3">
          {versions.engines.map((engine) => (
            <VersionRow
              key={engine.id}
              label={engine.label}
              value={engine.version ?? NOT_AVAILABLE}
            />
          ))}
        </dl>
      </SectionCard>
    </div>
  );
};
