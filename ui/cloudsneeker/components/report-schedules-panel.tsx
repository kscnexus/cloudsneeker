"use client";

import { Pencil, Plus, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  deleteReportSchedule,
  setReportScheduleEnabled,
} from "@/cloudsneeker/actions/reports";
import {
  reportTitle,
  type ReportCatalogEntry,
} from "@/cloudsneeker/lib/report-catalog";
import {
  defaultScheduleFormInput,
  scheduleFormInputFromResource,
} from "@/cloudsneeker/lib/report-form-schema";
import { describeReportCron } from "@/cloudsneeker/lib/report-schedule";
import { formatReportDate } from "@/cloudsneeker/lib/report-view";
import type { ReportScheduleResource } from "@/cloudsneeker/types/reports";
import { Button, Switch } from "@/components/shadcn";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/shadcn/dialog";

import type { ReportOption } from "./report-params-fields";
import { ReportScheduleForm } from "./report-schedule-form";

interface ReportSchedulesPanelProps {
  schedules: ReportScheduleResource[];
  catalog: ReportCatalogEntry[];
  providers: ReportOption[];
  frameworks: ReportOption[];
  canManage: boolean;
}

type Editing = { mode: "create" } | { mode: "edit"; schedule: ReportScheduleResource };

export const ReportSchedulesPanel = ({
  schedules,
  catalog,
  providers,
  frameworks,
  canManage,
}: ReportSchedulesPanelProps) => {
  const router = useRouter();
  const [editing, setEditing] = useState<Editing | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const finish = () => {
    setEditing(null);
    router.refresh();
  };

  const run = async (id: string, action: () => Promise<unknown>) => {
    setBusy(id);
    setError(null);
    const result = (await action()) as { error?: unknown } | undefined;
    setBusy(null);
    if (result?.error) {
      setError(
        typeof result.error === "string" ? result.error : "Request failed.",
      );
      return;
    }
    router.refresh();
  };

  const onDelete = (id: string) => {
    if (confirming !== id) {
      setConfirming(id);
      return;
    }
    setConfirming(null);
    void run(id, () => deleteReportSchedule(id));
  };

  if (!canManage) {
    return (
      <p className="text-text-neutral-secondary text-sm">
        Scheduled reports need the manage scans permission.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-text-neutral-secondary max-w-2xl text-sm">
          Email a report on a schedule. Each delivery uses the latest results
          at send time.
        </p>
        <Button
          type="button"
          size="sm"
          disabled={catalog.length === 0}
          onClick={() => setEditing({ mode: "create" })}
        >
          <Plus aria-hidden="true" />
          New schedule
        </Button>
      </div>

      {error ? <p className="text-text-error-primary text-sm">{error}</p> : null}

      {schedules.length === 0 ? (
        <p className="text-text-neutral-secondary border-border-neutral-secondary rounded-xl border border-dashed p-6 text-sm">
          No scheduled reports yet.
        </p>
      ) : (
        <ul className="divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-xl border">
          {schedules.map((schedule) => {
            const attributes = schedule.attributes;
            return (
              <li
                key={schedule.id}
                className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
              >
                <div className="flex min-w-0 flex-col gap-0.5">
                  <span className="text-text-neutral-primary font-medium">
                    {attributes.name}
                  </span>
                  <span className="text-text-neutral-secondary text-xs">
                    {reportTitle(attributes.report_type)} ·{" "}
                    {describeReportCron(
                      attributes.schedule_cron,
                      attributes.schedule_timezone,
                    )}{" "}
                    · {attributes.recipients.length} recipient(s)
                  </span>
                  <span className="text-text-neutral-tertiary text-xs">
                    Next {formatReportDate(attributes.next_run_at)} · Last{" "}
                    {formatReportDate(attributes.last_run_at)}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <Switch
                    checked={attributes.enabled}
                    disabled={busy === schedule.id}
                    aria-label={`${attributes.enabled ? "Disable" : "Enable"} ${attributes.name}`}
                    onCheckedChange={(checked: boolean) =>
                      run(schedule.id, () =>
                        setReportScheduleEnabled(schedule.id, checked),
                      )
                    }
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="xs"
                    onClick={() => setEditing({ mode: "edit", schedule })}
                  >
                    <Pencil aria-hidden="true" />
                    Edit
                  </Button>
                  <Button
                    type="button"
                    variant={confirming === schedule.id ? "destructive" : "ghost"}
                    size="xs"
                    disabled={busy === schedule.id}
                    onClick={() => onDelete(schedule.id)}
                  >
                    <Trash2 aria-hidden="true" />
                    {confirming === schedule.id ? "Confirm delete" : "Delete"}
                  </Button>
                </div>
              </li>
            );
          })}
        </ul>
      )}

      <Dialog
        open={editing !== null}
        onOpenChange={(open) => {
          if (!open) setEditing(null);
        }}
      >
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle>
              {editing?.mode === "edit" ? "Edit schedule" : "New schedule"}
            </DialogTitle>
            <DialogDescription>
              Reports are emailed through your configured email delivery.
            </DialogDescription>
          </DialogHeader>
          {editing ? (
            <ReportScheduleForm
              key={editing.mode === "edit" ? editing.schedule.id : "create"}
              catalog={catalog}
              providers={providers}
              frameworks={frameworks}
              initialValues={
                editing.mode === "edit"
                  ? scheduleFormInputFromResource(editing.schedule)
                  : defaultScheduleFormInput(catalog[0]?.id ?? "")
              }
              scheduleId={
                editing.mode === "edit" ? editing.schedule.id : undefined
              }
              onDone={finish}
              onCancel={() => setEditing(null)}
            />
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
};
