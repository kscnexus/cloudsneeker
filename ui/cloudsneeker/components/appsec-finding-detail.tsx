import Link from "next/link";
import type { ReactNode } from "react";

import {
  APPSEC_SEGMENT,
  appSecApplicationHref,
  appSecCategoryLabel,
  appSecFindingHref,
  appSecFindingLocation,
  appSecFindingsHref,
  dueLabel,
  formatAppSecDate,
  workspaceForCategory,
} from "@/cloudsneeker/lib/appsec";
import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import {
  APPSEC_CATEGORY,
  type AppSecCodeLine,
  type AppSecFindingAttributes,
  type AppSecFindingDetailAttributes,
  type AppSecResource,
} from "@/cloudsneeker/types/appsec";
import { cn } from "@/lib/utils";

import { AppSecTriageControl } from "./appsec-triage-control";
import {
  AppSecPriorityBadge,
  AppSecSeverityBadge,
  AppSecStateBadge,
  ROW_LINK_CLASS,
} from "./appsec-ui";
import { FindingTriageStatusBadge } from "./finding-triage-status-badge";
import { MuteFindingsButton } from "./mute-findings-button";
import { RunStatusBadge } from "./run-status-badge";
import { SectionCard } from "./section-card";

interface AppSecFindingDetailProps {
  findingId: string;
  finding: AppSecFindingDetailAttributes;
  canTriage: boolean;
}

interface Fact {
  label: string;
  value: ReactNode;
}

const text = (value: unknown): string =>
  typeof value === "string" ? value : "";
const list = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
const record = (value: unknown): Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

/** Label and value pairs; entries with no value are left out. */
const Facts = ({ facts }: { facts: Fact[] }) => {
  const present = facts.filter(
    (fact) =>
      fact.value !== null && fact.value !== undefined && fact.value !== "",
  );
  if (present.length === 0) return null;
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2 xl:grid-cols-3">
      {present.map((fact) => (
        <div key={fact.label} className="flex min-w-0 flex-col gap-0.5">
          <dt className="text-text-neutral-tertiary text-xs font-medium tracking-wide uppercase">
            {fact.label}
          </dt>
          <dd className="text-text-neutral-primary text-sm break-words">
            {fact.value}
          </dd>
        </div>
      ))}
    </dl>
  );
};

const CodeBlock = ({ lines }: { lines: AppSecCodeLine[] }) => (
  <pre className="border-border-neutral-secondary bg-bg-neutral-tertiary overflow-x-auto rounded-lg border p-3 text-xs">
    {lines.map((line, index) => (
      <div
        key={`${line.number ?? "x"}-${index}`}
        className={cn(
          "flex gap-3",
          line.is_cause && "text-text-neutral-primary font-semibold",
        )}
      >
        <span className="text-text-neutral-tertiary w-10 shrink-0 text-right tabular-nums select-none">
          {line.number ?? ""}
        </span>
        <code className="whitespace-pre">{line.content}</code>
      </div>
    ))}
  </pre>
);

const safeUrl = (value: string): string | null =>
  /^https?:\/\//i.test(value) ? value : null;

const ExternalLink = ({ href }: { href: string }) => {
  const url = safeUrl(href);
  if (!url) return <span className="break-all">{href}</span>;
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className="break-all underline"
    >
      {url}
    </a>
  );
};

const remediationFor = (finding: AppSecFindingDetailAttributes): string => {
  const details = finding.details;
  switch (finding.category) {
    case APPSEC_CATEGORY.VULNERABILITY:
      if (finding.fixed_version) {
        return `Upgrade ${finding.pkg_name} from ${finding.pkg_version || "the installed version"} to ${finding.fixed_version} or later, then rescan.`;
      }
      return `No fixed version of ${finding.pkg_name} is published yet${text(details.status) ? ` (vendor status: ${text(details.status)})` : ""}. Reduce exposure of the affected component, replace it, or record an exception with a review date.`;
    case APPSEC_CATEGORY.MISCONFIGURATION:
      return (
        text(details.resolution) ||
        "Change the configuration as the check description explains, then rescan."
      );
    case APPSEC_CATEGORY.SECRET:
      return "Revoke and rotate this credential now; treat it as leaked. Remove it from the file and from version history, load it from a secret manager, then rescan.";
    case APPSEC_CATEGORY.LICENSE:
      return `The ${finding.rule_id} license is classified as ${text(details.license_category) || "unknown"}. Check it against your license policy; replace the component, or record an exception.`;
    default:
      return text(details.resolution) || text(details.fix);
  }
};

const EVENT_LABEL: Record<string, string> = {
  detected: "Detected",
  fixed: "No longer reported; marked fixed",
  reopened: "Reported again; reopened",
  severity_changed: "Severity changed",
  suppressed: "Suppressed by a scan rule",
  unsuppressed: "Suppression removed",
};

const RelatedList = ({
  title,
  total,
  findings,
  moreHref,
}: {
  title: string;
  total: number;
  findings: AppSecResource<AppSecFindingAttributes>[];
  moreHref: string;
}) =>
  total > 0 ? (
    <div className="flex flex-col gap-2">
      <h3 className="text-text-neutral-primary text-sm font-semibold">
        {title} ({total})
      </h3>
      <ul className="divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-lg border">
        {findings.map(({ id, attributes }) => (
          <li
            key={id}
            className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm"
          >
            <div className="min-w-0">
              <Link href={appSecFindingHref(id)} className={ROW_LINK_CLASS}>
                {attributes.rule_id || attributes.title}
              </Link>
              <p className="text-text-neutral-tertiary truncate text-xs">
                {attributes.application_name ?? attributes.target_name} ·{" "}
                {appSecFindingLocation(attributes)}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <AppSecSeverityBadge severity={attributes.severity} />
              <AppSecStateBadge state={attributes.state} />
            </div>
          </li>
        ))}
      </ul>
      {total > findings.length ? (
        <Link href={moreHref} className="text-sm underline">
          Show all {total}
        </Link>
      ) : null}
    </div>
  ) : null;

/** Full record of one finding. Only fields that apply to it are shown. */
export const AppSecFindingDetail = ({
  findingId,
  finding,
  canTriage,
}: AppSecFindingDetailProps) => {
  const details = finding.details;
  const workspace = workspaceForCategory(finding.category);
  const code = Array.isArray(details.code)
    ? (details.code as AppSecCodeLine[])
    : [];
  const references = list(details.references);
  const kubernetes = record(details.kubernetes);
  const dataSource = record(details.data_source);
  const layer = record(details.layer);
  const instances = Array.isArray(details.instances)
    ? (details.instances as { version?: string }[])
    : [];
  const remediation = remediationFor(finding);
  const isVulnerability = finding.category === APPSEC_CATEGORY.VULNERABILITY;

  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        title="Summary"
        description={`${appSecCategoryLabel(finding.category)} · ${finding.rule_id}`}
        actions={
          <>
            <AppSecSeverityBadge severity={finding.severity} />
            <AppSecPriorityBadge
              priority={finding.priority}
              score={finding.priority_score}
            />
            <AppSecStateBadge state={finding.state} />
            <FindingTriageStatusBadge status={finding.triage_status} />
          </>
        }
      >
        <p className="text-text-neutral-primary text-base font-medium">
          {finding.title}
        </p>
        {finding.suppressed && finding.suppression.source === "mute_rule" ? (
          <p className="border-border-neutral-secondary text-text-neutral-secondary rounded-lg border px-3 py-2 text-sm">
            Muted by the mutelist rule{" "}
            <Link href="/mutelist" className="underline">
              {String(finding.suppression.rule_name ?? "")}
            </Link>
            {finding.suppression.reason
              ? `: ${String(finding.suppression.reason)}`
              : "."}
          </p>
        ) : finding.suppressed ? (
          <p className="border-border-neutral-secondary text-text-neutral-secondary rounded-lg border px-3 py-2 text-sm">
            Suppressed by a scan rule
            {finding.suppression.source
              ? ` (${finding.suppression.source})`
              : ""}
            {finding.suppression.status
              ? `: ${finding.suppression.status}`
              : ""}
            {finding.suppression.statement
              ? `. ${finding.suppression.statement}`
              : "."}
          </p>
        ) : null}
        <Facts
          facts={[
            {
              label: "Application",
              value: finding.application_id ? (
                <Link
                  className="underline"
                  href={appSecApplicationHref(finding.application_id)}
                >
                  {finding.application_name}
                </Link>
              ) : (
                "Not assigned"
              ),
            },
            {
              label: "Asset",
              value: (
                <Link
                  className="underline"
                  href={appSecurityHref(finding.target_id)}
                >
                  {finding.target_name}
                </Link>
              ),
            },
            {
              label: "Asset type",
              value: labelForTrivyMode(finding.target_type),
            },
            {
              label: "First detected",
              value: formatAppSecDate(finding.first_seen_at),
            },
            {
              label: "Last detected",
              value: formatAppSecDate(finding.last_seen_at),
            },
            {
              label: finding.state === "fixed" ? "Fixed" : "Deadline",
              value:
                finding.state === "fixed"
                  ? formatAppSecDate(finding.fixed_at)
                  : finding.due_at
                    ? `${formatAppSecDate(finding.due_at).slice(0, 10)} (${dueLabel(finding.due_at)})`
                    : "",
            },
            {
              label: "Reopened",
              value: finding.reopen_count
                ? `${finding.reopen_count} time(s)`
                : "",
            },
            {
              label: "Scanner severity",
              value: finding.source_severity,
            },
          ]}
        />
      </SectionCard>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <div className="flex min-w-0 flex-col gap-6 xl:col-span-2">
          <SectionCard title="Technical details">
            {finding.description ? (
              <p className="text-text-neutral-secondary text-sm whitespace-pre-line">
                {finding.description}
              </p>
            ) : null}
            {text(details.message) ? (
              <p className="text-text-neutral-primary text-sm">
                {text(details.message)}
              </p>
            ) : null}
            <Facts
              facts={[
                { label: "Package", value: finding.pkg_name },
                { label: "Installed version", value: finding.pkg_version },
                {
                  label: "Fixed version",
                  value: isVulnerability
                    ? finding.fixed_version || "None published"
                    : "",
                },
                { label: "Ecosystem", value: finding.ecosystem },
                {
                  label: "Dependency",
                  value:
                    details.direct_dependency === true
                      ? "Direct"
                      : details.direct_dependency === false
                        ? "Transitive"
                        : "",
                },
                { label: "Vendor status", value: text(details.status) },
                {
                  label: "CVSS base score",
                  value:
                    finding.cvss_score !== null
                      ? `${finding.cvss_score}${text(details.severity_source) ? ` (${text(details.severity_source)})` : ""}`
                      : "",
                },
                {
                  label: "Exploit probability (EPSS)",
                  value:
                    finding.epss_score !== null
                      ? `${(finding.epss_score * 100).toFixed(1)}%`
                      : "",
                },
                {
                  label: "Exploited in the wild",
                  value:
                    finding.known_exploited === null
                      ? ""
                      : finding.known_exploited
                        ? "Yes"
                        : "No",
                },
                {
                  label: "Weaknesses",
                  value: list(details.cwe_ids).join(", "),
                },
                {
                  label: "Other identifiers",
                  value: list(details.vendor_ids).join(", "),
                },
                { label: "Data source", value: text(dataSource.Name) },
                { label: "Package URL", value: finding.purl },
                {
                  label: "Also at versions",
                  value: instances
                    .map((item) => item.version)
                    .filter(Boolean)
                    .join(", "),
                },
                { label: "File", value: finding.file_path },
                {
                  label: "Lines",
                  value: finding.start_line
                    ? finding.end_line &&
                      finding.end_line !== finding.start_line
                      ? `${finding.start_line}–${finding.end_line}`
                      : String(finding.start_line)
                    : "",
                },
                { label: "Resource", value: finding.resource },
                {
                  label: "Kubernetes resource",
                  value: text(kubernetes.kind)
                    ? `${text(kubernetes.namespace) || "cluster"}/${text(kubernetes.kind)}/${text(kubernetes.name)}`
                    : "",
                },
                {
                  label: "Configuration type",
                  value:
                    finding.category === APPSEC_CATEGORY.MISCONFIGURATION
                      ? finding.finding_type
                      : "",
                },
                { label: "Cloud provider", value: text(details.provider) },
                { label: "Service", value: text(details.service) },
                { label: "Check namespace", value: text(details.namespace) },
                { label: "Secret type", value: text(details.category) },
                {
                  label: "License category",
                  value: text(details.license_category),
                },
                {
                  label: "Classifier confidence",
                  value:
                    typeof details.confidence === "number"
                      ? String(details.confidence)
                      : "",
                },
                { label: "Image layer", value: text(layer.DiffID) },
                { label: "Scan location", value: finding.location },
              ]}
            />
            {text(details.match) ? (
              <div className="flex flex-col gap-1">
                <span className="text-text-neutral-tertiary text-xs font-medium tracking-wide uppercase">
                  Match (masked)
                </span>
                <code className="bg-bg-neutral-tertiary rounded px-2 py-1 text-xs break-all">
                  {text(details.match)}
                </code>
              </div>
            ) : null}
            {code.length > 0 ? <CodeBlock lines={code} /> : null}
          </SectionCard>

          {remediation ? (
            <SectionCard title="Remediation">
              <p className="text-text-neutral-primary text-sm whitespace-pre-line">
                {remediation}
              </p>
              {text(details.fix) &&
              finding.category === APPSEC_CATEGORY.CODE ? (
                <pre className="bg-bg-neutral-tertiary overflow-x-auto rounded-lg p-3 text-xs">
                  {text(details.fix)}
                </pre>
              ) : null}
            </SectionCard>
          ) : null}

          {finding.primary_url || references.length > 0 ? (
            <SectionCard title="References">
              <ul className="flex flex-col gap-1 text-sm">
                {[finding.primary_url, ...references]
                  .filter(
                    (value, index, all) =>
                      value && all.indexOf(value) === index,
                  )
                  .slice(0, 25)
                  .map((reference) => (
                    <li key={reference}>
                      <ExternalLink href={reference} />
                    </li>
                  ))}
              </ul>
            </SectionCard>
          ) : null}

          {finding.related.same_rule_total > 0 ||
          finding.related.same_package_total > 0 ? (
            <SectionCard
              title="Related findings"
              description="The same issue elsewhere, and other issues in the same package."
            >
              <RelatedList
                title={`Same ${workspace.ruleLabel.toLowerCase()} on other assets or locations`}
                total={finding.related.same_rule_total}
                findings={finding.related.same_rule}
                moreHref={appSecFindingsHref(workspace.segment, {
                  rule: finding.rule_id,
                })}
              />
              <RelatedList
                title={`Other vulnerabilities in ${finding.pkg_name} on this asset`}
                total={finding.related.same_package_total}
                findings={finding.related.same_package}
                moreHref={appSecFindingsHref(APPSEC_SEGMENT.VULNERABILITIES, {
                  pkg: finding.pkg_name,
                  target: finding.target_id,
                })}
              />
            </SectionCard>
          ) : null}
        </div>

        <div className="flex min-w-0 flex-col gap-6">
          <SectionCard
            title="Priority"
            description="Calculated by the platform. The scanner severity is not changed."
          >
            <div className="flex items-center gap-3">
              <span className="text-text-neutral-primary text-3xl font-semibold tabular-nums">
                {finding.priority_score}
              </span>
              <AppSecPriorityBadge priority={finding.priority} />
            </div>
            <ul className="flex flex-col gap-1 text-sm">
              {finding.priority_factors.map((factor) => (
                <li
                  key={factor.key}
                  className="flex items-start justify-between gap-3"
                >
                  <span className="text-text-neutral-secondary">
                    {factor.label}
                  </span>
                  <span className="text-text-neutral-primary shrink-0 tabular-nums">
                    +{factor.points}
                  </span>
                </li>
              ))}
            </ul>
          </SectionCard>

          <SectionCard
            title="Triage"
            description="Status, notes and exceptions follow the finding across scans."
          >
            {canTriage ? (
              <div className="flex flex-col gap-3">
                <AppSecTriageControl
                  findingUid={finding.uid}
                  status={finding.triage_status}
                />
                {finding.suppressed ? null : (
                  <div className="flex flex-col gap-1">
                    <span className="text-text-neutral-secondary text-xs">
                      Muting hides the finding from active views, reports count
                      it as suppressed, and it stops raising alerts.
                    </span>
                    <MuteFindingsButton
                      findingUids={[finding.uid]}
                      label="Application Security finding"
                    />
                  </div>
                )}
              </div>
            ) : (
              <p className="text-text-neutral-secondary text-sm">
                Your role can read findings. Changing triage needs the manage
                scans permission.
              </p>
            )}
          </SectionCard>

          <SectionCard title="History">
            <ol className="flex flex-col gap-2 text-sm">
              {finding.events.map((event, index) => (
                <li
                  key={`${event.kind}-${event.at}-${index}`}
                  className="flex flex-col"
                >
                  <span className="text-text-neutral-primary">
                    {EVENT_LABEL[event.kind] ?? event.kind}
                    {event.kind === "severity_changed"
                      ? `: ${String(event.detail.from)} to ${String(event.detail.to)}`
                      : ""}
                  </span>
                  <span className="text-text-neutral-tertiary text-xs">
                    {formatAppSecDate(event.at)}
                    {event.run_id ? (
                      <>
                        {" · "}
                        <Link
                          className="underline"
                          href={appSecurityHref(
                            finding.target_id,
                            "runs",
                            event.run_id,
                          )}
                        >
                          scan
                        </Link>
                      </>
                    ) : null}
                  </span>
                </li>
              ))}
            </ol>
          </SectionCard>

          <SectionCard title="Recent scans of this asset">
            <ul className="flex flex-col gap-2 text-sm">
              {finding.recent_scans.map((scan) => (
                <li
                  key={scan.id}
                  className="flex items-center justify-between gap-2"
                >
                  <Link
                    className="underline"
                    href={appSecurityHref(finding.target_id, "runs", scan.id)}
                  >
                    {formatAppSecDate(scan.at)}
                  </Link>
                  <span className="flex items-center gap-2">
                    {scan.engine_version ? (
                      <span className="text-text-neutral-tertiary text-xs">
                        engine {scan.engine_version}
                      </span>
                    ) : null}
                    <RunStatusBadge status={scan.status} />
                  </span>
                </li>
              ))}
            </ul>
          </SectionCard>
        </div>
      </div>
      <p className="text-text-neutral-tertiary text-xs">Finding {findingId}</p>
    </div>
  );
};
