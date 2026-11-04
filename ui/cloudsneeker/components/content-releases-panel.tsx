import { Fragment, type ReactNode } from "react";

import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  CHANGE_KIND,
  type ChangeKind,
  type ChangeSet,
  type CheckChange,
  type ContentReleaseAttributes,
  type FrameworkChange,
} from "@/cloudsneeker/types/content-releases";
import { Badge } from "@/components/shadcn/badge/badge";
import {
  type Severity,
  SeverityBadge,
} from "@/components/shadcn/table/severity-badge";
import { getProviderDisplayName } from "@/types/providers";

const CHANGE_LABEL: Record<ChangeKind, string> = {
  [CHANGE_KIND.ADDED]: "Added",
  [CHANGE_KIND.CHANGED]: "Changed",
  [CHANGE_KIND.REMOVED]: "Removed",
};

const CHANGE_BADGE: Record<ChangeKind, "success" | "info" | "error"> = {
  [CHANGE_KIND.ADDED]: "success",
  [CHANGE_KIND.CHANGED]: "info",
  [CHANGE_KIND.REMOVED]: "error",
};

const CHANGE_KINDS = Object.values(CHANGE_KIND);

export const providerLabel = (provider: string): string =>
  provider === "multi-cloud" ? "Multi-cloud" : getProviderDisplayName(provider);

/** `2026-10-15`; the same on the server and in the browser. */
export const formatReleaseDate = (value: string | null): string | null => {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString().slice(0, 10);
};

const countOf = <T,>(changes: ChangeSet<T>): number =>
  CHANGE_KINDS.reduce((total, kind) => total + changes[kind].length, 0);

export const frameworkChangeSummary = (framework: FrameworkChange): string => {
  const parts: string[] = [];
  const plural = (count: number, word: string) =>
    `${count} ${word}${count === 1 ? "" : "s"}`;
  if (framework.requirements_added)
    parts.push(`${plural(framework.requirements_added, "requirement")} added`);
  if (framework.requirements_removed)
    parts.push(
      `${plural(framework.requirements_removed, "requirement")} removed`,
    );
  if (framework.requirements_remapped)
    parts.push(
      `${plural(framework.requirements_remapped, "requirement")} remapped to different checks`,
    );
  if (framework.fields?.length)
    parts.push(`${framework.fields.join(" and ")} updated`);
  return parts.join(", ");
};

const ChangeHeading = ({
  kind,
  count,
}: {
  kind: ChangeKind;
  count: number;
}) => (
  <h4 className="flex items-center gap-2 text-sm font-medium">
    <Badge variant={CHANGE_BADGE[kind]}>{CHANGE_LABEL[kind]}</Badge>
    <span className="text-text-neutral-tertiary tabular-nums">{count}</span>
  </h4>
);

const CheckRow = ({ check }: { check: CheckChange }) => (
  <li className="flex flex-col gap-0.5 py-2">
    <span className="text-text-neutral-primary text-sm">
      {check.title || check.id}
    </span>
    <span className="text-text-neutral-tertiary flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
      <span>{providerLabel(check.provider)}</span>
      <code className="break-all">{check.id}</code>
      {check.severity ? (
        <SeverityBadge severity={check.severity as Severity} />
      ) : null}
      {check.fields?.length ? (
        <span>Updated: {check.fields.join(", ")}</span>
      ) : null}
    </span>
  </li>
);

const FrameworkRow = ({ framework }: { framework: FrameworkChange }) => {
  const summary = frameworkChangeSummary(framework);
  return (
    <li className="flex flex-col gap-0.5 py-2">
      <span className="text-text-neutral-primary text-sm">
        {framework.name}
      </span>
      <span className="text-text-neutral-tertiary flex flex-wrap gap-x-3 gap-y-1 text-xs">
        <span>{providerLabel(framework.provider)}</span>
        {framework.version ? <span>Version {framework.version}</span> : null}
        <span>{framework.requirements} requirements</span>
        {summary ? <span>{summary}</span> : null}
      </span>
    </li>
  );
};

interface ChangeGroupProps<T> {
  title: string;
  changes: ChangeSet<T>;
  renderItem: (item: T) => ReactNode;
}

const ChangeGroup = <T extends { id: string }>({
  title,
  changes,
  renderItem,
}: ChangeGroupProps<T>) => {
  const total = countOf(changes);
  if (!total) return null;
  return (
    <details className="group border-border-neutral-secondary rounded-md border">
      <summary className="text-text-neutral-primary flex cursor-pointer items-center justify-between gap-3 px-3 py-2 text-sm font-medium">
        <span>{title}</span>
        <span className="text-text-neutral-tertiary flex gap-3 text-xs font-normal tabular-nums">
          {CHANGE_KINDS.filter((kind) => changes[kind].length).map((kind) => (
            <span key={kind}>
              {changes[kind].length} {CHANGE_LABEL[kind].toLowerCase()}
            </span>
          ))}
        </span>
      </summary>
      <div className="flex flex-col gap-4 px-3 pb-3">
        {CHANGE_KINDS.filter((kind) => changes[kind].length).map((kind) => (
          <section key={kind} className="flex flex-col gap-1">
            <ChangeHeading kind={kind} count={changes[kind].length} />
            <ul className="divide-border-neutral-secondary divide-y">
              {changes[kind].map((item) => (
                <Fragment key={item.id}>{renderItem(item)}</Fragment>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </details>
  );
};

export const ReleaseCard = ({
  release,
}: {
  release: ContentReleaseAttributes;
}) => {
  const date = formatReleaseDate(release.released_at);
  const hasChanges = countOf(release.checks) + countOf(release.frameworks) > 0;
  const description = [
    release.current ? "Running now" : date ? `Released ${date}` : null,
    `Compared with ${release.previous_version}`,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <SectionCard
      title={`Release ${release.version}`}
      description={description}
      actions={
        release.current ? <Badge variant="success">Current</Badge> : null
      }
      contentClassName="flex flex-col gap-3"
    >
      {hasChanges ? (
        <>
          <ChangeGroup
            title="Checks"
            changes={release.checks}
            renderItem={(check) => <CheckRow check={check} />}
          />
          <ChangeGroup
            title="Compliance frameworks"
            changes={release.frameworks}
            renderItem={(framework) => <FrameworkRow framework={framework} />}
          />
        </>
      ) : (
        <p className="text-text-neutral-tertiary text-sm">
          No checks or compliance frameworks changed in this release.
        </p>
      )}
    </SectionCard>
  );
};

export const ContentReleasesPanel = ({
  releases,
}: {
  releases: ContentReleaseAttributes[];
}) => (
  <div className="flex flex-col gap-6">
    {releases.map((release) => (
      <ReleaseCard key={release.version} release={release} />
    ))}
  </div>
);
