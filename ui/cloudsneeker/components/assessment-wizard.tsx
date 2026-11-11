"use client";

import {
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Eye,
  FileCheck2,
  Loader2,
  ShieldAlert,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { createReportRun, getReportRun } from "@/cloudsneeker/actions/reports";
import {
  ASSESSMENT_PERIOD,
  ASSESSMENT_TYPE_IDS,
  type AssessmentSection,
  assessmentSummary,
  type AssessmentTypeId,
  buildAssessmentPayload,
  initialWizardState,
  PERIOD_OPTIONS,
  QUALITY_STATUS,
  qualityLabel,
  type ScopeSource,
  SECTION_LABELS,
  sectionsFor,
  sourcesFor,
  stepError,
  supportsFrameworks,
  WIZARD_STEP,
  WIZARD_STEPS,
  type WizardState,
  withReportType,
} from "@/cloudsneeker/lib/assessment-wizard";
import { reportTitle } from "@/cloudsneeker/lib/report-catalog";
import {
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import { reportsHref } from "@/cloudsneeker/routes";
import {
  REPORT_FORMAT,
  REPORT_RUN_STATUS,
  type ReportRunResource,
  type SelectableReportFormat,
} from "@/cloudsneeker/types/reports";
import { Badge, Button, Input, Label } from "@/components/shadcn";

import { FormAlert } from "./form-layout";
import { ReportDownloadLinks } from "./report-download-links";

const POLL_MS = 3000;

const TYPE_COPY: Record<AssessmentTypeId, string> = {
  security_assessment:
    "Leadership view across cloud, application security, and governance.",
  appsec_assessment:
    "Dependencies, code weaknesses, secrets, and templates for engineering.",
  cloud_assessment: "Cloud configuration per account and service.",
  governance_assessment:
    "Policy violations and assessed compliance frameworks.",
};

const FORMAT_OPTIONS: { id: SelectableReportFormat; label: string }[] = [
  { id: REPORT_FORMAT.PDF, label: "PDF report" },
  { id: REPORT_FORMAT.CSV, label: "CSV, every finding with its source record" },
  { id: REPORT_FORMAT.XLSX, label: "Excel workbook" },
];

const PROGRESS_LABEL: Record<string, string> = {
  [REPORT_RUN_STATUS.PENDING]: "Queued",
  [REPORT_RUN_STATUS.RUNNING]:
    "Collecting findings, checking accuracy, and rendering",
  [REPORT_RUN_STATUS.COMPLETED]: "Ready",
  [REPORT_RUN_STATUS.FAILED]: "Failed",
};

export interface FrameworkOption {
  id: string;
  label: string;
}

interface AssessmentWizardProps {
  sources: ScopeSource[];
  frameworks: FrameworkOption[];
  canGenerate: boolean;
}

const toggle = <T extends string>(list: T[], value: T): T[] =>
  list.includes(value)
    ? list.filter((item) => item !== value)
    : [...list, value];

const errorMessage = (result: unknown): string | null => {
  if (result && typeof result === "object" && "error" in result) {
    const error = (result as { error?: unknown }).error;
    if (error) return typeof error === "string" ? error : "The request failed.";
  }
  return null;
};

export const AssessmentWizard = ({
  sources,
  frameworks,
  canGenerate,
}: AssessmentWizardProps) => {
  const router = useRouter();
  const [state, setState] = useState<WizardState>(initialWizardState());
  const [stepIndex, setStepIndex] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [run, setRun] = useState<ReportRunResource | null>(null);

  const step = WIZARD_STEPS[stepIndex].id;
  const available = sourcesFor(state.reportType, sources);
  const runStatus = run?.attributes.status;
  const active =
    runStatus === REPORT_RUN_STATUS.PENDING ||
    runStatus === REPORT_RUN_STATUS.RUNNING;

  useEffect(() => {
    if (!run || !active) return;
    const timer = setTimeout(async () => {
      const result = await getReportRun(run.id);
      const next = (result as { data?: ReportRunResource } | undefined)?.data;
      if (next) setRun(next);
      if (
        next &&
        !(
          next.attributes.status === REPORT_RUN_STATUS.PENDING ||
          next.attributes.status === REPORT_RUN_STATUS.RUNNING
        )
      ) {
        router.refresh();
      }
    }, POLL_MS);
    return () => clearTimeout(timer);
  }, [run, active, router]);

  const goTo = (index: number) => {
    if (index > stepIndex) {
      const message = stepError(step, state);
      if (message) {
        setError(message);
        return;
      }
    }
    setError(null);
    setStepIndex(index);
  };

  const generate = async () => {
    const message = stepError(WIZARD_STEP.GENERATE, state);
    if (message) {
      setError(message);
      return;
    }
    setSubmitting(true);
    setError(null);
    const result = await createReportRun(buildAssessmentPayload(state));
    setSubmitting(false);
    const failure = errorMessage(result);
    if (failure) {
      setError(failure);
      return;
    }
    const created = (result as { data?: ReportRunResource } | undefined)?.data;
    if (created) setRun(created);
  };

  const update = (patch: Partial<WizardState>) =>
    setState((current) => ({ ...current, ...patch }));

  return (
    <div className="flex flex-col gap-5">
      <ol className="flex flex-wrap gap-2" aria-label="Wizard steps">
        {WIZARD_STEPS.map((item, index) => {
          const current = index === stepIndex;
          const done = index < stepIndex;
          return (
            <li key={item.id}>
              <button
                type="button"
                onClick={() => goTo(index)}
                disabled={Boolean(run) || index > stepIndex + 1}
                aria-current={current ? "step" : undefined}
                className={[
                  "flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium transition-colors",
                  current
                    ? "border-button-tertiary bg-button-tertiary/10 text-text-neutral-primary"
                    : done
                      ? "border-border-neutral-secondary text-text-neutral-secondary"
                      : "border-border-neutral-secondary text-text-neutral-tertiary",
                ].join(" ")}
              >
                <span className="tabular-nums">{index + 1}</span>
                {item.label}
                {done ? (
                  <CheckCircle2 className="size-3.5" aria-hidden="true" />
                ) : null}
              </button>
            </li>
          );
        })}
      </ol>

      {step === WIZARD_STEP.TYPE ? (
        <fieldset className="grid gap-3 md:grid-cols-2">
          <legend className="sr-only">Report type</legend>
          {ASSESSMENT_TYPE_IDS.map((type) => {
            const selected = state.reportType === type;
            return (
              <label
                key={type}
                className={[
                  "flex cursor-pointer flex-col gap-1 rounded-xl border p-4 transition-colors",
                  selected
                    ? "border-button-tertiary bg-button-tertiary/5"
                    : "border-border-neutral-secondary hover:bg-bg-neutral-tertiary/60",
                ].join(" ")}
              >
                <span className="flex items-center gap-2">
                  <input
                    type="radio"
                    name="assessment-type"
                    className={FORM_CHECK_CLASS}
                    checked={selected}
                    onChange={() =>
                      setState((current) => withReportType(current, type))
                    }
                  />
                  <span className="text-text-neutral-primary text-sm font-semibold">
                    {reportTitle(type)}
                  </span>
                </span>
                <span className="text-text-neutral-secondary pl-6 text-xs">
                  {TYPE_COPY[type]}
                </span>
              </label>
            );
          })}
        </fieldset>
      ) : null}

      {step === WIZARD_STEP.SCOPE ? (
        <div className="flex flex-col gap-4">
          <fieldset className="flex flex-col gap-2">
            <legend className="text-text-neutral-primary mb-1 text-sm font-medium">
              Sources
            </legend>
            <p className="text-text-neutral-secondary text-xs">
              {state.providerIds.length === 0
                ? `All ${available.length} relevant source(s) you can see are included.`
                : `${state.providerIds.length} of ${available.length} selected.`}
            </p>
            {available.length > 0 ? (
              <div className="border-border-neutral-secondary grid max-h-56 gap-1 overflow-y-auto rounded-lg border p-2 sm:grid-cols-2">
                {available.map((source) => (
                  <label key={source.id} className={FORM_CHOICE_CLASS}>
                    <input
                      type="checkbox"
                      className={FORM_CHECK_CLASS}
                      checked={state.providerIds.includes(source.id)}
                      onChange={() =>
                        update({
                          providerIds: toggle(state.providerIds, source.id),
                        })
                      }
                    />
                    <span className="min-w-0 truncate">
                      {source.label}
                      <span className="text-text-neutral-tertiary">
                        {" "}
                        · {source.providerType}
                      </span>
                    </span>
                  </label>
                ))}
              </div>
            ) : (
              <p className="text-text-neutral-secondary text-sm">
                No relevant source is connected. The report will mark every area
                as not assessed.
              </p>
            )}
          </fieldset>
          {supportsFrameworks(state.reportType) && frameworks.length > 0 ? (
            <fieldset className="flex flex-col gap-2">
              <legend className="text-text-neutral-primary mb-1 text-sm font-medium">
                Compliance frameworks
              </legend>
              <p className="text-text-neutral-secondary text-xs">
                None selected reports every framework with results. Frameworks
                are reported as assessed controls, never as certification.
              </p>
              <div className="border-border-neutral-secondary grid max-h-48 gap-1 overflow-y-auto rounded-lg border p-2 sm:grid-cols-2">
                {frameworks.map((framework) => (
                  <label key={framework.id} className={FORM_CHOICE_CLASS}>
                    <input
                      type="checkbox"
                      className={FORM_CHECK_CLASS}
                      checked={state.frameworks.includes(framework.id)}
                      onChange={() =>
                        update({
                          frameworks: toggle(state.frameworks, framework.id),
                        })
                      }
                    />
                    <span className="min-w-0 truncate">{framework.label}</span>
                  </label>
                ))}
              </div>
            </fieldset>
          ) : null}
          <div className="flex max-w-xs flex-col gap-1">
            <Label htmlFor="assessment-stale">
              Mark a source stale after (days)
            </Label>
            <Input
              id="assessment-stale"
              type="number"
              min={1}
              max={90}
              value={state.staleDays}
              onChange={(event) =>
                update({ staleDays: Number(event.target.value) })
              }
            />
          </div>
        </div>
      ) : null}

      {step === WIZARD_STEP.PERIOD ? (
        <div className="flex flex-col gap-4">
          <fieldset className="grid gap-2 md:grid-cols-2">
            <legend className="sr-only">Assessment period</legend>
            {PERIOD_OPTIONS.map((option) => (
              <label
                key={option.id}
                className={`${FORM_CHOICE_CLASS} border-border-neutral-secondary rounded-lg border p-3`}
              >
                <input
                  type="radio"
                  name="assessment-period"
                  className={FORM_CHECK_CLASS}
                  checked={state.period === option.id}
                  onChange={() => update({ period: option.id })}
                />
                <span className="flex flex-col">
                  <span className="font-medium">{option.label}</span>
                  <span className="text-text-neutral-secondary text-xs">
                    {option.hint}
                  </span>
                </span>
              </label>
            ))}
          </fieldset>
          {state.period === ASSESSMENT_PERIOD.CUSTOM ? (
            <div className="grid max-w-md gap-3 sm:grid-cols-2">
              <div className="flex flex-col gap-1">
                <Label htmlFor="assessment-from">From</Label>
                <Input
                  id="assessment-from"
                  type="date"
                  value={state.dateFrom}
                  onChange={(event) => update({ dateFrom: event.target.value })}
                />
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="assessment-to">To</Label>
                <Input
                  id="assessment-to"
                  type="date"
                  value={state.dateTo}
                  onChange={(event) => update({ dateTo: event.target.value })}
                />
              </div>
            </div>
          ) : null}
        </div>
      ) : null}

      {step === WIZARD_STEP.SECTIONS ? (
        <fieldset className="grid gap-2 md:grid-cols-2">
          <legend className="text-text-neutral-secondary mb-2 text-xs">
            Cover, scope and coverage, executive summary, methodology, and
            quality control are always included.
          </legend>
          {sectionsFor(state.reportType).map((section: AssessmentSection) => (
            <label
              key={section}
              className={`${FORM_CHOICE_CLASS} border-border-neutral-secondary rounded-lg border p-3`}
            >
              <input
                type="checkbox"
                className={FORM_CHECK_CLASS}
                checked={state.sections.includes(section)}
                onChange={() =>
                  update({ sections: toggle(state.sections, section) })
                }
              />
              <span className="flex flex-col">
                <span className="font-medium">
                  {SECTION_LABELS[section].label}
                </span>
                <span className="text-text-neutral-secondary text-xs">
                  {SECTION_LABELS[section].hint}
                </span>
              </span>
            </label>
          ))}
        </fieldset>
      ) : null}

      {step === WIZARD_STEP.GENERATE ? (
        <div className="flex flex-col gap-4">
          <dl className="border-border-neutral-secondary grid gap-x-6 gap-y-2 rounded-xl border p-4 text-sm sm:grid-cols-2">
            <div>
              <dt className="text-text-neutral-tertiary text-xs">Report</dt>
              <dd className="text-text-neutral-primary font-medium">
                {reportTitle(state.reportType)}
              </dd>
            </div>
            <div>
              <dt className="text-text-neutral-tertiary text-xs">Period</dt>
              <dd className="text-text-neutral-primary">
                {
                  PERIOD_OPTIONS.find((option) => option.id === state.period)
                    ?.label
                }
                {state.period === ASSESSMENT_PERIOD.CUSTOM
                  ? ` (${state.dateFrom || "start"} to ${state.dateTo || "now"})`
                  : ""}
              </dd>
            </div>
            <div>
              <dt className="text-text-neutral-tertiary text-xs">Sources</dt>
              <dd className="text-text-neutral-primary">
                {state.providerIds.length || `All ${available.length}`}
              </dd>
            </div>
            <div>
              <dt className="text-text-neutral-tertiary text-xs">Sections</dt>
              <dd className="text-text-neutral-primary">
                {state.sections
                  .map((section) => SECTION_LABELS[section].label)
                  .join(", ") || "Core pages only"}
              </dd>
            </div>
          </dl>
          {available.length === 0 ? (
            <FormAlert message="No relevant source is connected, so every area will read 'Not assessed'." />
          ) : null}
          <fieldset className="flex flex-col gap-2">
            <legend className="text-text-neutral-primary mb-1 text-sm font-medium">
              Files
            </legend>
            {FORMAT_OPTIONS.map((format) => (
              <label key={format.id} className={FORM_CHOICE_CLASS}>
                <input
                  type="checkbox"
                  className={FORM_CHECK_CLASS}
                  checked={state.formats.includes(format.id)}
                  disabled={Boolean(run)}
                  onChange={() =>
                    update({ formats: toggle(state.formats, format.id) })
                  }
                />
                {format.label}
              </label>
            ))}
          </fieldset>
          {run ? <RunProgress run={run} /> : null}
        </div>
      ) : null}

      <FormAlert message={error} />

      <div className="flex flex-wrap items-center gap-2">
        {stepIndex > 0 && !run ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => goTo(stepIndex - 1)}
          >
            <ChevronLeft aria-hidden="true" />
            Back
          </Button>
        ) : null}
        {step !== WIZARD_STEP.GENERATE ? (
          <Button type="button" onClick={() => goTo(stepIndex + 1)}>
            Next
            <ChevronRight aria-hidden="true" />
          </Button>
        ) : run && !active ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              setRun(null);
              setStepIndex(0);
            }}
          >
            New report
          </Button>
        ) : (
          <Button
            type="button"
            onClick={generate}
            disabled={!canGenerate || submitting || active}
          >
            {submitting || active ? (
              <Loader2 className="animate-spin" aria-hidden="true" />
            ) : (
              <FileCheck2 aria-hidden="true" />
            )}
            {active ? "Generating" : "Generate report"}
          </Button>
        )}
        {!canGenerate ? (
          <span className="text-text-neutral-secondary text-xs">
            Generating reports needs the manage scans permission.
          </span>
        ) : null}
      </div>
    </div>
  );
};

const RunProgress = ({ run }: { run: ReportRunResource }) => {
  const attributes = run.attributes;
  const summary = assessmentSummary(attributes);
  const completed = attributes.status === REPORT_RUN_STATUS.COMPLETED;
  const failed = attributes.status === REPORT_RUN_STATUS.FAILED;
  const tone = !completed
    ? failed
      ? "error"
      : "info"
    : summary.distributable === false
      ? "error"
      : summary.qualityStatus === QUALITY_STATUS.WARN
        ? "warning"
        : "success";
  return (
    <section
      aria-live="polite"
      className="border-border-neutral-secondary flex flex-col gap-3 rounded-xl border p-4"
    >
      <div className="flex flex-wrap items-center gap-2">
        {!completed && !failed ? (
          <Loader2 className="size-4 animate-spin" aria-hidden="true" />
        ) : null}
        {failed ? (
          <ShieldAlert
            className="text-text-error-primary size-4"
            aria-hidden="true"
          />
        ) : null}
        <span className="text-text-neutral-primary text-sm font-medium">
          {PROGRESS_LABEL[attributes.status] ?? attributes.status}
        </span>
        {completed ? (
          <Badge variant={tone}>{qualityLabel(summary)}</Badge>
        ) : null}
        {completed && summary.grade ? (
          <span className="text-text-neutral-secondary text-xs">
            Grade {summary.grade}
            {summary.score !== null ? ` · ${summary.score.toFixed(0)}/100` : ""}
            {summary.pages ? ` · ${summary.pages} pages` : ""}
          </span>
        ) : null}
      </div>
      {failed && attributes.error ? (
        <p className="text-text-error-primary text-xs">{attributes.error}</p>
      ) : null}
      {completed && summary.qualitySummary ? (
        <p className="text-text-neutral-secondary text-xs">
          Quality control: {summary.qualitySummary}
          {summary.failedChecks.length
            ? ` Failed: ${summary.failedChecks.join(", ")}.`
            : ""}
        </p>
      ) : null}
      {completed && summary.warnings.length ? (
        <ul className="text-text-warning-primary flex list-disc flex-col gap-1 pl-5 text-xs">
          {summary.warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      ) : null}
      {completed ? (
        <div className="flex flex-wrap gap-2">
          <ReportDownloadLinks
            runId={run.id}
            formats={attributes.available_formats ?? []}
            size="sm"
          />
          <Button asChild variant="ghost" size="sm">
            <Link href={reportsHref(run.id)}>
              <Eye aria-hidden="true" />
              View in app
            </Link>
          </Button>
        </div>
      ) : null}
    </section>
  );
};
