"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import {
  Boxes,
  ClipboardCheck,
  Cloud,
  Code2,
  Container,
  FileCode2,
  KeyRound,
  type LucideIcon,
  Package,
  Presentation,
  Scale,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useForm } from "react-hook-form";

import { createReportRun } from "@/cloudsneeker/actions/reports";
import {
  REPORT_AUDIENCE,
  type ReportCatalogEntry,
} from "@/cloudsneeker/lib/report-catalog";
import {
  reportGenerateFormSchema,
  reportRunPayloadFromForm,
  type ReportGenerateFormInput,
  type ReportGenerateFormValues,
} from "@/cloudsneeker/lib/report-form-schema";
import {
  REPORT_FORMAT,
  REPORT_TYPE_ID,
  type ReportTypeId,
} from "@/cloudsneeker/types/reports";
import { Badge, Button } from "@/components/shadcn";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/shadcn/dialog";

import {
  asReportParamsForm,
  ReportParamsFields,
  type ReportOption,
} from "./report-params-fields";

export const REPORT_TYPE_ICON: Record<ReportTypeId, LucideIcon> = {
  [REPORT_TYPE_ID.EXECUTIVE]: Presentation,
  [REPORT_TYPE_ID.CLOUD_POSTURE]: Cloud,
  [REPORT_TYPE_ID.COMPLIANCE]: ClipboardCheck,
  [REPORT_TYPE_ID.SCA]: Package,
  [REPORT_TYPE_ID.SAST]: Code2,
  [REPORT_TYPE_ID.CONTAINER]: Container,
  [REPORT_TYPE_ID.IAC]: FileCode2,
  [REPORT_TYPE_ID.SECRETS]: KeyRound,
  [REPORT_TYPE_ID.GOVERNANCE]: Scale,
};

export const reportTypeIcon = (id: string): LucideIcon =>
  REPORT_TYPE_ICON[id as ReportTypeId] ?? Boxes;

interface ReportCatalogGridProps {
  catalog: ReportCatalogEntry[];
  providers: ReportOption[];
  frameworks: ReportOption[];
}

const defaultValues = (reportType: string): ReportGenerateFormInput => ({
  reportType,
  providerIds: [],
  dateFrom: "",
  dateTo: "",
  severityFloor: "",
  complianceId: "",
  formats: [REPORT_FORMAT.PDF],
});

export const ReportCatalogGrid = ({
  catalog,
  providers,
  frameworks,
}: ReportCatalogGridProps) => {
  const router = useRouter();
  const [selected, setSelected] = useState<ReportCatalogEntry | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const form = useForm<
    ReportGenerateFormInput,
    unknown,
    ReportGenerateFormValues
  >({
    resolver: zodResolver(reportGenerateFormSchema),
    defaultValues: defaultValues(""),
  });

  const openFor = (entry: ReportCatalogEntry) => {
    form.reset(defaultValues(entry.id));
    setError(null);
    setSelected(entry);
  };

  const onSubmit = form.handleSubmit(async (values) => {
    setSaving(true);
    setError(null);
    const result = await createReportRun(reportRunPayloadFromForm(values));
    setSaving(false);
    if (result && "error" in result && result.error) {
      setError(
        typeof result.error === "string"
          ? result.error
          : "Could not start the report.",
      );
      return;
    }
    setSelected(null);
    router.refresh();
  });

  if (catalog.length === 0) {
    return (
      <p className="text-text-neutral-secondary text-sm">
        Reports are not available right now.
      </p>
    );
  }

  return (
    <>
      <ul className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {catalog.map((entry) => {
          const Icon = reportTypeIcon(entry.id);
          return (
            <li
              key={entry.id}
              className="border-border-neutral-secondary bg-bg-neutral-secondary flex flex-col gap-3 rounded-xl border p-5"
            >
              <div className="flex items-start gap-3">
                <span className="bg-bg-data-info/15 text-bg-data-info flex size-10 shrink-0 items-center justify-center rounded-lg">
                  <Icon aria-hidden="true" className="size-5" />
                </span>
                <div className="flex min-w-0 flex-col gap-1">
                  <h3 className="text-text-neutral-primary font-semibold">
                    {entry.title}
                  </h3>
                  {entry.audience === REPORT_AUDIENCE.MANAGEMENT ? (
                    <Badge variant="info" size="sm">
                      For leadership
                    </Badge>
                  ) : null}
                </div>
              </div>
              <p className="text-text-neutral-secondary flex-1 text-sm">
                {entry.description}
              </p>
              <div>
                <Button type="button" size="sm" onClick={() => openFor(entry)}>
                  Generate
                </Button>
              </div>
            </li>
          );
        })}
      </ul>

      <Dialog
        open={selected !== null}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        <DialogContent className="max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Generate {selected?.title}</DialogTitle>
            <DialogDescription>
              The report is prepared in the background and appears under
              Recent reports when it is ready.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={onSubmit} className="flex flex-col gap-4">
            <ReportParamsFields
              form={asReportParamsForm(form)}
              idPrefix="report-generate"
              providers={providers}
              frameworks={frameworks}
            />
            {error ? (
              <p className="text-text-error-primary text-sm">{error}</p>
            ) : null}
            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={() => setSelected(null)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={saving}>
                {saving ? "Starting…" : "Generate report"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
};
