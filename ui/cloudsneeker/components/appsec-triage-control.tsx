"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { updateFindingTriage } from "@/cloudsneeker/actions/finding-triage";
import { actionError } from "@/cloudsneeker/lib/appsec";
import {
  TRIAGE_STATUS_FILTERS,
  triageStatusLabel,
} from "@/cloudsneeker/lib/finding-triage";
import { FORM_SELECT_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { Button, Textarea } from "@/components/shadcn";
import {
  FINDING_TRIAGE_STATUS,
  type FindingTriageStatus,
} from "@/types/findings-triage";

import { FormAlert, FormField } from "./form-layout";

interface AppSecTriageControlProps {
  findingUid: string;
  status: string;
}

/** Statuses that close a finding need a written reason. */
const REASON_REQUIRED: readonly string[] = [
  FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
  FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
];

/** Sets the triage status of a finding through the platform triage API. */
export const AppSecTriageControl = ({
  findingUid,
  status,
}: AppSecTriageControlProps) => {
  const router = useRouter();
  const [selected, setSelected] = useState(status);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const needsReason = REASON_REQUIRED.includes(selected);
  const unchanged = selected === status && note.trim() === "";

  const onSave = async () => {
    if (needsReason && selected !== status && note.trim().length < 5) {
      setError("Give a reason for accepting the risk or marking it false.");
      return;
    }
    setSaving(true);
    setError(null);
    const result = await updateFindingTriage(findingUid, {
      ...(selected !== status
        ? { status: selected as FindingTriageStatus }
        : {}),
      ...(note.trim() ? { note: note.trim() } : {}),
    });
    setSaving(false);
    const failure = actionError(result);
    if (failure) {
      setError(failure);
      return;
    }
    setNote("");
    router.refresh();
  };

  return (
    <div className="flex flex-col gap-3">
      <FormField id="appsec-triage-status" label="Triage status">
        <select
          id="appsec-triage-status"
          className={FORM_SELECT_CLASS}
          value={selected}
          onChange={(event) => setSelected(event.target.value)}
        >
          {TRIAGE_STATUS_FILTERS.map((item) => (
            <option key={item} value={item}>
              {triageStatusLabel(item)}
            </option>
          ))}
        </select>
      </FormField>
      <FormField
        id="appsec-triage-note"
        label={needsReason ? "Reason" : "Note"}
        optional={!needsReason}
        help="Saved in the finding's triage thread and the audit log."
      >
        <Textarea
          id="appsec-triage-note"
          value={note}
          rows={3}
          maxLength={2000}
          onChange={(event) => setNote(event.target.value)}
        />
      </FormField>
      <FormAlert message={error} />
      <div>
        <Button
          type="button"
          size="sm"
          onClick={onSave}
          disabled={saving || unchanged}
        >
          {saving ? "Saving…" : "Save triage"}
        </Button>
      </div>
    </div>
  );
};
