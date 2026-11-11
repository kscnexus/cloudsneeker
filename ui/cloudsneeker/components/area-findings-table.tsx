"use client";

import { ChevronDown, ChevronRight } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Fragment, useState, useTransition } from "react";

import {
  bulkUpdateFindingTriage,
  updateFindingTriage,
} from "@/cloudsneeker/actions/finding-triage";
import { securityCategoryShort } from "@/cloudsneeker/lib/app-security-categories";
import {
  type AreaConfig,
  appSecurityFindingHref,
} from "@/cloudsneeker/lib/area-findings";
import {
  TRIAGE_STATUS_FILTERS,
  triageStatusLabel,
} from "@/cloudsneeker/lib/finding-triage";
import { formatReportDate } from "@/cloudsneeker/lib/report-view";
import {
  defaultRiskAcceptance,
  RISK_ACCEPTED_STATUS,
  type RiskAcceptanceInput,
  riskAcceptanceProblem,
} from "@/cloudsneeker/lib/risk-acceptance";
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

import {
  AreaFindingExploitBadges,
  AreaFindingExploitDetails,
} from "./area-finding-exploit";
import { AreaFindingFixCell, AreaFindingFixDetails } from "./area-finding-fix";
import { FindingTriageStatusBadge } from "./finding-triage-status-badge";
import { MuteFindingsButton } from "./mute-findings-button";
import { ReportSeverityBadge } from "./report-severity-badge";
import { RiskAcceptanceFields } from "./risk-acceptance-fields";
import { RiskPriorityBadge } from "./risk-priority-badge";

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
  // EB-019: finding whose risk acceptance form is open, and the form values
  // (shared with the bulk bar).
  const [accepting, setAccepting] = useState<string | null>(null);
  const [acceptance, setAcceptance] = useState<RiskAcceptanceInput>(() =>
    defaultRiskAcceptance(),
  );

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

  const acceptanceProblem = riskAcceptanceProblem(acceptance);
  const cleanedAcceptance = {
    risk_reason: acceptance.risk_reason.trim(),
    risk_expires_on: acceptance.risk_expires_on,
  };
  const resetAcceptance = () => {
    setAccepting(null);
    setAcceptance(defaultRiskAcceptance());
  };

  const applyBulk = () => {
    const accept = bulkStatus === RISK_ACCEPTED_STATUS;
    if (accept && acceptanceProblem) {
      setError(acceptanceProblem);
      return;
    }
    run(
      () =>
        accept
          ? bulkUpdateFindingTriage(
              Array.from(selected),
              bulkStatus,
              undefined,
              cleanedAcceptance,
            )
          : bulkUpdateFindingTriage(Array.from(selected), bulkStatus),
      () => {
        setSelected(new Set());
        if (accept) resetAcceptance();
      },
    );
  };

  const setStatus = (uid: string, status: FindingTriageStatus) => {
    if (status === RISK_ACCEPTED_STATUS) {
      // Accepting a risk needs a reason and an expiry first.
      setError(null);
      setAccepting(uid);
      return;
    }
    run(() => updateFindingTriage(uid, { status }));
  };

  const acceptRisk = (uid: string) => {
    if (acceptanceProblem) {
      setError(acceptanceProblem);
      return;
    }
    run(
      () =>
        updateFindingTriage(uid, {
          status: RISK_ACCEPTED_STATUS,
          ...cleanedAcceptance,
        }),
      resetAcceptance,
    );
  };

  const addNote = (uid: string) =>
    run(
      () => updateFindingTriage(uid, { note: note.trim() }),
      () => setNote(""),
    );

  const columns = [
    config.checkLabel,
    config.resourceLabel,
    config.sourceLabel,
    ...(config.showCategory ? ["Category"] : []),
    "Severity",
    ...(config.showCategory ? ["Priority"] : []),
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
            {selected.size} selected on this page
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
          {bulkStatus === RISK_ACCEPTED_STATUS ? (
            <div className="basis-full">
              <RiskAcceptanceFields
                idPrefix="area-bulk-risk"
                value={acceptance}
                onChange={setAcceptance}
                disabled={pending}
              />
            </div>
          ) : null}
          <Button size="xs" onClick={applyBulk} disabled={pending}>
            {pending
              ? "Saving…"
              : bulkStatus === RISK_ACCEPTED_STATUS
                ? "Accept risk"
                : "Set status"}
          </Button>
          <MuteFindingsButton
            findingUids={Array.from(selected)}
            label={config.name}
            onMuted={() => setSelected(new Set())}
          />
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
                    {config.showCategory ? (
                      <td className="text-text-neutral-secondary px-3 py-2 align-top text-xs whitespace-nowrap">
                        {securityCategoryShort(finding.security_category)}
                      </td>
                    ) : null}
                    <td className="px-3 py-2 align-top">
                      <ReportSeverityBadge severity={finding.severity} />
                      {config.showExploit ? (
                        <AreaFindingExploitBadges finding={finding} />
                      ) : null}
                    </td>
                    {config.showCategory ? (
                      <td className="px-3 py-2 align-top">
                        <RiskPriorityBadge
                          priority={finding.priority}
                          overdue={finding.overdue}
                        />
                      </td>
                    ) : null}
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
                      {finding.triage_status === RISK_ACCEPTED_STATUS &&
                      finding.risk_expires_on ? (
                        <span
                          className="text-text-neutral-tertiary mt-1 block text-xs"
                          title={finding.risk_reason || undefined}
                        >
                          Until {finding.risk_expires_on}
                        </span>
                      ) : null}
                    </td>
                    <td className="text-text-neutral-secondary px-3 py-2 align-top text-xs whitespace-nowrap">
                      {formatReportDate(finding.last_seen_at)}
                    </td>
                  </tr>
                  {accepting === finding.uid ? (
                    <tr className="bg-bg-neutral-secondary">
                      <td />
                      <td colSpan={columns.length} className="px-3 py-3">
                        <div
                          role="group"
                          aria-label={`Accept the risk of ${finding.title}`}
                          className="flex flex-col gap-2"
                        >
                          <RiskAcceptanceFields
                            idPrefix={`risk-${finding.uid}`}
                            value={acceptance}
                            onChange={setAcceptance}
                            disabled={pending}
                          />
                          <div className="flex gap-2">
                            <Button
                              size="xs"
                              onClick={() => acceptRisk(finding.uid)}
                              disabled={pending}
                            >
                              {pending ? "Saving…" : "Accept risk"}
                            </Button>
                            <Button
                              size="xs"
                              variant="ghost"
                              onClick={resetAcceptance}
                              disabled={pending}
                            >
                              Cancel
                            </Button>
                          </div>
                        </div>
                      </td>
                    </tr>
                  ) : null}
                  {isOpen ? (
                    <tr className="bg-bg-neutral-secondary">
                      <td />
                      <td colSpan={columns.length} className="px-3 pb-4">
                        <dl className="grid gap-3 text-xs sm:grid-cols-2">
                          {config.showCategory ? (
                            <div className="sm:col-span-2">
                              <Link
                                href={appSecurityFindingHref(finding.uid)}
                                className="text-text-neutral-primary text-sm font-medium underline underline-offset-2"
                              >
                                Open the full finding
                              </Link>
                            </div>
                          ) : null}
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
                          {config.showExploit ? (
                            <AreaFindingExploitDetails finding={finding} />
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
