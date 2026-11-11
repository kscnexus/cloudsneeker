"use client";

import { Info } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useState, useTransition } from "react";

import {
  createAlert, // cloudsneeker-hook
  deleteAlert,
  disableAlert,
  enableAlert,
  updateAlert,
} from "@/app/(prowler)/alerts/_actions";
import {
  ALERT_TRIGGER_KINDS,
  type AlertRule,
} from "@/app/(prowler)/alerts/_types";
import { showDocumentationLinks } from "@/cloudsneeker/docs-links"; // cloudsneeker-hook
import {
  NEW_ALERT_AREA_PARAM,
  NEW_ALERT_PARAM,
} from "@/cloudsneeker/lib/alert-areas"; // cloudsneeker-hook
import type { FindingArea } from "@/cloudsneeker/types/area-findings"; // cloudsneeker-hook
import { Button, useToast } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { DOCS_URLS } from "@/lib/external-urls";
import type { MetaDataProps, ScanEntity } from "@/types";
import type { ProviderProps } from "@/types/providers";

import { toAlertPayload } from "../_lib/alert-adapter";
import { getAlertMutationError } from "../_lib/alert-errors";
import type {
  AlertFormSubmitResult,
  AlertFormValues,
} from "../_types/alert-form";

import { AlertFormModal } from "./alert-form-modal";
import { AlertsEmptyState } from "./alerts-empty-state";
import { AlertsTable } from "./alerts-table";

interface AlertsManagerProps {
  alerts: AlertRule[];
  meta?: MetaDataProps;
  loadError: string | null;
  providers: ProviderProps[];
  completedScanIds: string[];
  scanDetails: { [key: string]: ScanEntity }[];
  uniqueRegions: string[];
  uniqueServices: string[];
  uniqueResourceTypes: string[];
  uniqueCategories: string[];
  uniqueGroups: string[];
  initialEditingAlert?: AlertRule | null;
  /** cloudsneeker-hook: `/alerts?new=1&area=...` opens a new rule. */
  initialNewArea?: FindingArea | null;
}

const ALERTS_FINDINGS_HREF =
  "/findings?filter[muted]=false&filter[status__in]=FAIL";

export const AlertsManager = ({
  alerts,
  meta,
  loadError,
  providers,
  completedScanIds,
  scanDetails,
  uniqueRegions,
  uniqueServices,
  uniqueResourceTypes,
  uniqueCategories,
  uniqueGroups,
  initialEditingAlert = null,
  initialNewArea = null,
}: AlertsManagerProps) => {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const { toast } = useToast();
  const [, startTransition] = useTransition();
  const [modalOpen, setModalOpen] = useState(
    Boolean(initialEditingAlert) || Boolean(initialNewArea),
  );
  // cloudsneeker-hook: areas of a rule created on this page (null = editing).
  const [newAlertAreas, setNewAlertAreas] = useState<FindingArea[] | null>(
    !initialEditingAlert && initialNewArea ? [initialNewArea] : null,
  );
  const [editingAlert, setEditingRule] = useState<AlertRule | null>(
    initialEditingAlert,
  );
  const [mutatingId, setMutatingId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<AlertRule | null>(null);

  const refresh = () => startTransition(() => router.refresh());

  const replaceEditParam = (alertId: string | null) => {
    const params = new URLSearchParams(searchParams.toString());
    if (alertId) {
      params.set("edit", alertId);
    } else {
      params.delete("edit");
    }
    params.delete(NEW_ALERT_PARAM); // cloudsneeker-hook
    params.delete(NEW_ALERT_AREA_PARAM);

    const queryString = params.toString();
    router.replace(queryString ? `${pathname}?${queryString}` : pathname, {
      scroll: false,
    });
  };

  const closeModal = (open: boolean) => {
    setModalOpen(open);
    if (!open) {
      setEditingRule(null);
      setNewAlertAreas(null);
      replaceEditParam(null);
    }
  };

  const submitAlert = async (
    values: AlertFormValues,
  ): Promise<AlertFormSubmitResult> => {
    if (!editingAlert) {
      // cloudsneeker-hook: new rules can be created here for any module.
      if (!newAlertAreas) {
        return { ok: false, error: "Create alerts from Findings." };
      }
      const created = await createAlert(toAlertPayload(values));
      if (created?.error) {
        return { ok: false, error: getAlertMutationError(created) };
      }
      toast({
        title: "Alert created",
        description: created.data.attributes.name,
      });
      refresh();
      return { ok: true, alertId: created.data.id };
    }
    const payload = toAlertPayload(values);
    const result = await updateAlert(editingAlert.id, payload);
    if (result?.error) {
      return {
        ok: false,
        error: getAlertMutationError(result),
      };
    }
    toast({
      title: "Alert updated",
      description: result.data.attributes.name,
    });
    refresh();
    return { ok: true, alertId: result.data.id };
  };

  const toggleAlert = async (alert: AlertRule) => {
    setMutatingId(alert.id);
    const result = alert.attributes.enabled
      ? await disableAlert(alert.id)
      : await enableAlert(alert.id);
    setMutatingId(null);
    if (result?.error) {
      toast({
        variant: "destructive",
        title: "Alert update failed",
        description: getAlertMutationError(result),
      });
      return;
    }
    toast({
      title: alert.attributes.enabled ? "Alert disabled" : "Alert enabled",
      description: result.data.attributes.name,
    });
    refresh();
  };

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    setMutatingId(pendingDelete.id);
    const result = await deleteAlert(pendingDelete.id);
    setMutatingId(null);
    if (result?.error) {
      toast({
        variant: "destructive",
        title: "Alert delete failed",
        description: getAlertMutationError(result),
      });
      return;
    }
    setPendingDelete(null);
    refresh();
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="flex max-w-3xl flex-col gap-2">
          <div className="text-text-neutral-secondary flex flex-wrap items-center gap-1 text-sm">
            <Info className="size-4 shrink-0" />
            <span>
              Get notified when findings match the conditions you define.
            </span>
            <span>To create an alert, go to</span>
            <Button
              variant="link"
              size="link-sm"
              className="h-auto p-0"
              asChild
            >
              <Link href={ALERTS_FINDINGS_HREF}>Findings</Link>
            </Button>
            <span>, or create one here for any module.</span>
            {showDocumentationLinks() && (
              <>
                <span>Learn more about configuring the Alerts</span>
                <Button
                  variant="link"
                  size="link-sm"
                  className="h-auto p-0"
                  asChild
                >
                  <a
                    href={DOCS_URLS.ALERTS}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <span>here.</span>
                  </a>
                </Button>
              </>
            )}
          </div>
        </div>
      </div>

      {/* cloudsneeker-hook: new rule for Cloud Security, Application Security or Governance */}
      <div className="flex justify-end">
        <Button
          onClick={() => {
            setEditingRule(null);
            setNewAlertAreas([]);
            setModalOpen(true);
          }}
        >
          New alert
        </Button>
      </div>

      {loadError && (
        <div className="border-destructive/40 bg-destructive/10 text-destructive rounded-md border p-4 text-sm">
          Failed to load alerts: {loadError}
        </div>
      )}

      {alerts.length === 0 && !loadError ? (
        <AlertsEmptyState />
      ) : (
        <AlertsTable
          alerts={alerts}
          meta={meta}
          mutatingId={mutatingId}
          onEdit={(alert) => {
            setEditingRule(alert);
            setModalOpen(true);
            replaceEditParam(alert.id);
          }}
          onToggleEnabled={toggleAlert}
          onDelete={setPendingDelete}
        />
      )}

      <AlertFormModal
        key={editingAlert?.id ?? (newAlertAreas ? "new" : "edit")}
        open={modalOpen}
        defaultFrequency={ALERT_TRIGGER_KINDS.AFTER_SCAN}
        providers={providers}
        completedScanIds={completedScanIds}
        scanDetails={scanDetails}
        uniqueRegions={uniqueRegions}
        uniqueServices={uniqueServices}
        uniqueResourceTypes={uniqueResourceTypes}
        uniqueCategories={uniqueCategories}
        uniqueGroups={uniqueGroups}
        editingAlert={editingAlert}
        editableFilters={Boolean(newAlertAreas)}
        initialAreas={newAlertAreas ?? []}
        defaultName={newAlertAreas ? "New alert" : undefined}
        onOpenChange={closeModal}
        onSubmit={submitAlert}
      />

      <Modal
        open={Boolean(pendingDelete)}
        onOpenChange={(open) => !open && setPendingDelete(null)}
        title="Delete alert"
        description={
          pendingDelete
            ? `Delete "${pendingDelete.attributes.name}"? This alert will stop evaluating.`
            : ""
        }
        size="md"
      >
        <div className="flex justify-end gap-2 pt-4">
          <Button variant="outline" onClick={() => setPendingDelete(null)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={mutatingId === pendingDelete?.id}
            onClick={confirmDelete}
          >
            Delete alert
          </Button>
        </div>
      </Modal>
    </div>
  );
};
