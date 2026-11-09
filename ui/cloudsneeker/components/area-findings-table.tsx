"use client";

import { ChevronDown, ChevronRight } from "lucide-react";
import { useRouter } from "next/navigation";
import { Fragment, useState, useTransition } from "react";

import {
  bulkUpdateFindingTriage,
  updateFindingTriage,
} from "@/cloudsneeker/actions/finding-triage";
import type { AreaConfig } from "@/cloudsneeker/lib/area-findings";
import {
  TRIAGE_STATUS_FILTERS,
  triageStatusLabel,
} from "@/cloudsneeker/lib/finding-triage";
import { formatReportDate } from "@/cloudsneeker/lib/report-view";
import {
  FORM_CHECK_CLASS,
  FORM_SELECT_CLASS,
  TABLE_BODY_CLASS,
  TABLE_CLASS,
  TABLE_FRAME_CLASS,
  TABLE_HEADER_CELL_CLASS,
  TABLE_HEAD_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import type { AreaFindingResource } from "@/cloudsneeker/types/area-findings";
import { Button, Textarea } from "@/components/shadcn";
import { cn } from "@/lib/utils";
import {
  FINDING_TRIAGE_NOTE_MAX_LENGTH,
  type FindingTriageStatus,
} from "@/types/findings-triage";

import { AreaFindingFixCell, AreaFindingFixDetails } from "./area-finding-fix";
import { FindingTriageStatusBadge } from "./finding-triage-status-badge";
import { ReportSeverityBadge } from "./report-severity-badge";

interface AreaFindingsTableProps {
  config: AreaConfig;
  findings: AreaFindingResource[];
  canTriage: boolean;
}

const errorOf = (result: unknown): string | null => {
  if (!result || typeof result !== "object" || !("error" in result)) {
    return null;
  }
  const error = (result as { error?: unknown }).error;
  if (!error) return null;
  return typeof error === "string" ? error : "The change was not saved.";
};

const resourceText = (finding: AreaFindingResource["attributes"]): string =>
  finding.location || finding.resource_name || finding.resource_id || "—";

/** One area's findings with triage status, bulk triage and notes. */
export const AreaFindingsTable = ({
  config,
  findings,
  canTriage,
}: AreaFindingsTableProps) => {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<string | null>(null);
  const [bulkStatus, setBulkStatus] = useState<FindingTriageStatus>(
    TRIAGE_STATUS_FILTERS[1],
  );
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  const uids = findings.map((finding) => finding.attributes.uid);
  const allSelected = uids.length > 0 && uids.every((uid) => selected.has(uid));

  const run = (action: () => Promise<unknown>, after?: () => void) => {
    setError(null);
    startTransition(async () => {
      const failure = errorOf(await action());
      if (failure) {
        setError(failure);
        return;
      }
      after?.();
      router.refresh();
    });
  };

  const toggle = (uid: string) => {
    const next = new Set(selected);
    if (next.has(uid)) next.delete(uid);
    else next.add(uid);
    setSelected(next);
  };

  const toggleAll = () => setSelected(allSelected ? new Set() : new Set(uids));

  const applyBulk = () =>
    run(
      () => bulkUpdateFindingTriage(Array.from(selected), bulkStatus),
      () => setSelected(new Set()),
    );

  const setStatus = (uid: string, status: FindingTriageStatus) =>
    run(() => updateFindingTriage(uid, { status }));

  const addNote = (uid: string) =>
    run(
      () => updateFindingTriage(uid, { note: note.trim() }),
      () => setNote(""),
    );

  const columns = [
    config.checkLabel,
    config.resourceLabel,
    config.sourceLabel,
    "Severity",
    ...(config.showFix ? ["Fix"] : []),
    "Triage",
    "Last seen",
  ];

  return (
    <div className="flex flex-col gap-3">
      {canTriage && selected.size > 0 ? (
        <div
          role="region"
          aria-label="Bulk triage"
          className="border-border-neutral-secondary bg-bg-neutral-tertiary flex flex-wrap items-center gap-2 rounded-lg border p-3 text-sm"
        >
          <span className="text-text-neutral-primary font-medium">
            {selected.size} selected
          </span>
          <label className="sr-only" htmlFor="area-bulk-status">
            Triage status for the selected findings
          </label>
          <select
            id="area-bulk-status"
            className={cn(FORM_SELECT_CLASS, "h-8 w-auto")}
            value={bulkStatus}
            onChange={(event) =>
              setBulkStatus(event.target.value as FindingTriageStatus)
            }
          >
            {TRIAGE_STATUS_FILTERS.map((status) => (
              <option key={status} value={status}>
                {triageStatusLabel(status)}
              </option>
            ))}
          </select>
          <Button size="xs" onClick={applyBulk} disabled={pending}>
            {pending ? "Saving…" : "Set status"}
          </Button>
          <Button
            size="xs"
            variant="ghost"
            onClick={() => setSelected(new Set())}
            disabled={pending}
          >
            Clear
          </Button>
        </div>
      ) : null}
      {error ? (
        <p role="alert" className="text-text-error-primary text-sm">
          {error}
        </p>
      ) : null}
      <div className={TABLE_FRAME_CLASS}>
        <table className={TABLE_CLASS}>
          <thead className={TABLE_HEAD_CLASS}>
            <tr>
              <th scope="col" className="w-8 px-3 py-2">
                {canTriage ? (
                  <input
                    type="checkbox"
                    className={FORM_CHECK_CLASS}
                    aria-label="Select all findings on this page"
                    checked={allSelected}
                    onChange={toggleAll}
                  />
                ) : (
                  <span className="sr-only">Details</span>
                )}
              </th>
              {columns.map((column) => (
                <th
                  key={column}
                  scope="col"
                  className={TABLE_HEADER_CELL_CLASS}
                >
                  {column}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className={TABLE_BODY_CLASS}>
            {findings.map(({ attributes: finding }) => {
              const isOpen = expanded === finding.uid;
              return (
                <Fragment key={finding.uid}>
                  <tr className={cn(isOpen && "bg-bg-neutral-secondary")}>
                    <td className="px-3 py-2 align-top">
                      {canTriage ? (
                        <input
                          type="checkbox"
                          className={FORM_CHECK_CLASS}
                          aria-label={`Select ${finding.title}`}
                          checked={selected.has(finding.uid)}
                          onChange={() => toggle(finding.uid)}
                        />
                      ) : null}
                    </td>
                    <td className="max-w-md px-3 py-2 align-top">
                      <button
                        type="button"
                        className="flex min-w-0 items-start gap-1 text-left"
                        aria-expanded={isOpen}
                        onClick={() => setExpanded(isOpen ? null : finding.uid)}
                      >
                        {isOpen ? (
                          <ChevronDown
                            aria-hidden="true"
                            className="mt-0.5 size-4 shrink-0"
                          />
                        ) : (
                          <ChevronRight
                            aria-hidden="true"
                            className="mt-0.5 size-4 shrink-0"
                          />
                        )}
                        <span className="flex min-w-0 flex-col">
                          <span className="text-text-neutral-primary line-clamp-2 font-medium">
                            {finding.title}
                          </span>
                          <span className="text-text-neutral-tertiary truncate font-mono text-xs">
                            {finding.check_id}
                          </span>
                        </span>
                      </button>
                    </td>
                    <td
                      className="text-text-neutral-secondary max-w-xs truncate px-3 py-2 align-top font-mono text-xs"
                      title={finding.resource_id || undefined}
                    >
                      {resourceText(finding)}
                    </td>
                    <td className="text-text-neutral-secondary px-3 py-2 align-top text-xs">
                      {finding.source_name || "—"}
                    </td>
                    <td className="px-3 py-2 align-top">
                      <ReportSeverityBadge severity={finding.severity} />
                    </td>
                    {config.showFix ? (
                      <td className="px-3 py-2 align-top whitespace-nowrap">
                        <AreaFindingFixCell finding={finding} />
                      </td>
                    ) : null}
                    <td className="px-3 py-2 align-top whitespace-nowrap">
                      {canTriage ? (
                        <select
                          aria-label={`Triage status of ${finding.title}`}
                          className={cn(FORM_SELECT_CLASS, "h-8 w-auto")}
                          value={finding.triage_status}
                          disabled={pending}
                          onChange={(event) =>
                            setStatus(
                              finding.uid,
                              event.target.value as FindingTriageStatus,
                            )
                          }
                        >
                          {TRIAGE_STATUS_FILTERS.map((status) => (
                            <option key={status} value={status}>
                              {triageStatusLabel(status)}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <FindingTriageStatusBadge
                          status={finding.triage_status}
                        />
                      )}
                    </td>
                    <td className="text-text-neutral-secondary px-3 py-2 align-top text-xs whitespace-nowrap">
                      {formatReportDate(finding.last_seen_at)}
                    </td>
                  </tr>
                  {isOpen ? (
                    <tr className="bg-bg-neutral-secondary">
                      <td />
                      <td colSpan={columns.length} className="px-3 pb-4">
                        <dl className="grid gap-3 text-xs sm:grid-cols-2">
                          {finding.description ? (
                            <div className="sm:col-span-2">
                              <dt className="text-text-neutral-tertiary font-semibold">
                                Description
                              </dt>
                              <dd className="text-text-neutral-primary whitespace-pre-line">
                                {finding.description}
                              </dd>
                            </div>
                          ) : null}
                          <AreaFindingFixDetails finding={finding} />
                          <div>
                            <dt className="text-text-neutral-tertiary font-semibold">
                              {config.resourceLabel}
                            </dt>
                            <dd className="text-text-neutral-primary font-mono break-all">
                              {finding.resource_id || resourceText(finding)}
                            </dd>
                          </div>
                          <div>
                            <dt className="text-text-neutral-tertiary font-semibold">
                              Type
                            </dt>
                            <dd className="text-text-neutral-primary">
                              {[finding.resource_type, finding.region]
                                .filter(Boolean)
                                .join(" · ") || "—"}
                            </dd>
                          </div>
                          {finding.categories.length ? (
                            <div className="sm:col-span-2">
                              <dt className="text-text-neutral-tertiary font-semibold">
                                Categories
                              </dt>
                              <dd className="text-text-neutral-primary">
                                {finding.categories.join(", ")}
                              </dd>
                            </div>
                          ) : null}
                          <div>
                            <dt className="text-text-neutral-tertiary font-semibold">
                              First seen
                            </dt>
                            <dd className="text-text-neutral-primary">
                              {formatReportDate(finding.first_seen_at)}
                            </dd>
                          </div>
                          <div className="sm:col-span-2">
                            <dt className="text-text-neutral-tertiary font-semibold">
                              Latest note
                              {finding.triage_notes_count > 1
                                ? ` (${finding.triage_notes_count} notes)`
                                : ""}
                            </dt>
                            <dd className="text-text-neutral-primary whitespace-pre-line">
                              {finding.triage_latest_note || "No notes yet."}
                            </dd>
                          </div>
                        </dl>
                        {canTriage ? (
                          <div className="mt-3 flex max-w-xl flex-col gap-2">
                            <label
                              htmlFor={`note-${finding.uid}`}
                              className="text-text-neutral-secondary text-xs font-semibold"
                            >
                              Add a note
                            </label>
                            <Textarea
                              id={`note-${finding.uid}`}
                              value={note}
                              maxLength={FINDING_TRIAGE_NOTE_MAX_LENGTH}
                              onChange={(event) => setNote(event.target.value)}
                            />
                            <div>
                              <Button
                                size="xs"
                                onClick={() => addNote(finding.uid)}
                                disabled={pending || !note.trim()}
                              >
                                Save note
                              </Button>
                            </div>
                          </div>
                        ) : null}
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
