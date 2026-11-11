"use client";

import { VolumeX } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { muteAreaFindings } from "@/cloudsneeker/actions/finding-triage";
import { Button, Input } from "@/components/shadcn";

const REASON_MIN = 3;
const REASON_MAX = 500;

interface MuteFindingsButtonProps {
  findingUids: string[];
  /** Used in the rule name, e.g. "Application Security finding". */
  label: string;
  onMuted?: () => void;
}

const errorText = (result: unknown): string | null => {
  if (!result || typeof result !== "object" || !("error" in result)) {
    return null;
  }
  const error = (result as { error?: unknown }).error;
  if (!error) return null;
  return typeof error === "string" ? error : "The findings were not muted.";
};

/** Mute findings of any module through the shared mutelist. */
export const MuteFindingsButton = ({
  findingUids,
  label,
  onMuted,
}: MuteFindingsButtonProps) => {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();

  const count = findingUids.length;
  const trimmed = reason.trim();

  const submit = () => {
    if (trimmed.length < REASON_MIN) {
      setError(`Give a reason of at least ${REASON_MIN} characters.`);
      return;
    }
    setError(null);
    startTransition(async () => {
      const name =
        count === 1 ? `Muted ${label}` : `Muted ${count} ${label} findings`;
      const result = await muteAreaFindings({
        findingUids,
        name: name.slice(0, 100),
        reason: trimmed.slice(0, REASON_MAX),
      });
      const failure = errorText(result);
      if (failure) {
        setError(failure);
        return;
      }
      const skipped =
        (result as { meta?: { skipped_uids?: string[] } })?.meta
          ?.skipped_uids ?? [];
      setMessage(
        skipped.length > 0
          ? `Muted ${count - skipped.length} of ${count}; ${skipped.length} were already muted or not current.`
          : `Muted ${count} finding${count === 1 ? "" : "s"}. Find them in the Mutelist.`,
      );
      setOpen(false);
      setReason("");
      onMuted?.();
      router.refresh();
    });
  };

  if (!open) {
    return (
      <span className="inline-flex items-center gap-2">
        <Button
          size="xs"
          variant="outline"
          disabled={count === 0}
          onClick={() => {
            setMessage(null);
            setOpen(true);
          }}
        >
          <VolumeX aria-hidden="true" />
          Mute
        </Button>
        {message ? (
          <span role="status" className="text-text-neutral-secondary text-xs">
            {message}
          </span>
        ) : null}
      </span>
    );
  }

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <label className="sr-only" htmlFor="mute-reason">
        Reason for muting
      </label>
      <Input
        id="mute-reason"
        className="h-8 w-64"
        placeholder="Reason (required)"
        maxLength={REASON_MAX}
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        disabled={pending}
      />
      <Button size="xs" onClick={submit} disabled={pending}>
        {pending ? "Muting…" : `Mute ${count}`}
      </Button>
      <Button
        size="xs"
        variant="ghost"
        onClick={() => setOpen(false)}
        disabled={pending}
      >
        Cancel
      </Button>
      {error ? (
        <span role="alert" className="text-text-error-primary text-xs">
          {error}
        </span>
      ) : null}
    </span>
  );
};
