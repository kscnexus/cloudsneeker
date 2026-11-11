"use client";

import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { updateAlertEvent } from "@/cloudsneeker/actions/alert-events";
import {
  type AlertEventStatus,
  alertEventTransitions,
} from "@/cloudsneeker/lib/alert-history";
import { Button, Input } from "@/components/shadcn";

const NOTE_MAX = 2000;

interface AlertEventActionsProps {
  eventId: string;
  status: AlertEventStatus;
  note: string;
}

const errorText = (result: unknown): string | null => {
  if (!result || typeof result !== "object" || !("error" in result)) {
    return null;
  }
  const error = (result as { error?: unknown }).error;
  if (!error) return null;
  return typeof error === "string" ? error : "The alert was not updated.";
};

/** Status buttons and an optional note for one alert event. */
export const AlertEventActions = ({
  eventId,
  status,
  note,
}: AlertEventActionsProps) => {
  const router = useRouter();
  const [draft, setDraft] = useState(note);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const submit = (nextStatus: AlertEventStatus) => {
    setError(null);
    startTransition(async () => {
      const trimmed = draft.trim();
      const result = await updateAlertEvent(eventId, {
        status: nextStatus,
        ...(trimmed !== note ? { note: trimmed.slice(0, NOTE_MAX) } : {}),
      });
      const failure = errorText(result);
      if (failure) {
        setError(failure);
        return;
      }
      router.refresh();
    });
  };

  return (
    <div className="flex flex-col gap-2">
      <Input
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
        maxLength={NOTE_MAX}
        placeholder="Note (optional)"
        aria-label="Alert note"
        disabled={pending}
      />
      <div className="flex flex-wrap gap-2">
        {alertEventTransitions(status).map((transition) => (
          <Button
            key={transition.status}
            type="button"
            size="xs"
            variant="outline"
            disabled={pending}
            onClick={() => submit(transition.status)}
          >
            {transition.label}
          </Button>
        ))}
      </div>
      {error ? (
        <p role="alert" className="text-text-error-primary text-xs">
          {error}
        </p>
      ) : null}
    </div>
  );
};
