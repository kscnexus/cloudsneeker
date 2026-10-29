"use client";

import { Check, Copy, Share2 } from "lucide-react";
import { useState } from "react";

import { createReportShareLink } from "@/cloudsneeker/actions/reports";
import {
  DEFAULT_SHARE_LINK_HOURS,
  SHARE_LINK_EXPIRY_OPTIONS,
} from "@/cloudsneeker/lib/report-form-schema";
import { formatReportDate } from "@/cloudsneeker/lib/report-view";
import { sharedReportHref } from "@/cloudsneeker/routes";
import type { ReportShareLinkResource } from "@/cloudsneeker/types/reports";
import { Button, Input, Label } from "@/components/shadcn";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/shadcn/dialog";

interface ReportShareDialogProps {
  runId: string;
  reportName: string;
  disabled?: boolean;
  size?: "sm" | "xs";
}

interface CreatedLink {
  url: string;
  expiresAt: string;
}

export const ReportShareDialog = ({
  runId,
  reportName,
  disabled,
  size = "sm",
}: ReportShareDialogProps) => {
  const [open, setOpen] = useState(false);
  const [hours, setHours] = useState<number>(DEFAULT_SHARE_LINK_HOURS);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<CreatedLink | null>(null);
  const [copied, setCopied] = useState(false);

  const reset = (next: boolean) => {
    setOpen(next);
    if (!next) {
      // The raw token is shown once; closing the dialog discards it.
      setCreated(null);
      setError(null);
      setCopied(false);
      setHours(DEFAULT_SHARE_LINK_HOURS);
    }
  };

  const onCreate = async () => {
    setSaving(true);
    setError(null);
    const result = await createReportShareLink(runId, hours);
    setSaving(false);
    const link = result?.data as ReportShareLinkResource | undefined;
    const token = link?.attributes?.token;
    if ((result && "error" in result && result.error) || !link || !token) {
      setError(
        typeof result?.error === "string"
          ? result.error
          : "Could not create the share link.",
      );
      return;
    }
    setCreated({
      url: `${window.location.origin}${sharedReportHref(token)}`,
      expiresAt: link.attributes.expires_at,
    });
  };

  const onCopy = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.url);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <>
      <Button
        type="button"
        variant="outline"
        size={size}
        disabled={disabled}
        onClick={() => reset(true)}
      >
        <Share2 aria-hidden="true" />
        Share
      </Button>
      <Dialog open={open} onOpenChange={reset}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Share {reportName}</DialogTitle>
            <DialogDescription>
              Anyone with the link can view this report without signing in
              until it expires or you revoke it.
            </DialogDescription>
          </DialogHeader>

          {created ? (
            <div className="flex flex-col gap-3">
              <Label htmlFor="report-share-url">Share link</Label>
              <div className="flex gap-2">
                <Input
                  id="report-share-url"
                  readOnly
                  value={created.url}
                  onFocus={(event) => event.currentTarget.select()}
                />
                <Button type="button" size="sm" onClick={onCopy}>
                  {copied ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
                  {copied ? "Copied" : "Copy"}
                </Button>
              </div>
              <p className="text-text-warning-primary text-xs">
                Copy it now. The link is shown only once; create a new one if
                you lose it.
              </p>
              <p className="text-text-neutral-secondary text-xs">
                Expires {formatReportDate(created.expiresAt)}.
              </p>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              <Label htmlFor="report-share-expiry">Link expires after</Label>
              <select
                id="report-share-expiry"
                className="border-border-neutral-secondary bg-bg-neutral-primary text-text-neutral-primary rounded-md border px-3 py-2 text-sm"
                value={hours}
                onChange={(event) => setHours(Number(event.target.value))}
              >
                {SHARE_LINK_EXPIRY_OPTIONS.map((option) => (
                  <option key={option.hours} value={option.hours}>
                    {option.label}
                  </option>
                ))}
              </select>
              {error ? (
                <p className="text-text-error-primary text-sm">{error}</p>
              ) : null}
            </div>
          )}

          <DialogFooter>
            {created ? (
              <Button type="button" variant="outline" onClick={() => reset(false)}>
                Done
              </Button>
            ) : (
              <>
                <Button type="button" variant="ghost" onClick={() => reset(false)}>
                  Cancel
                </Button>
                <Button type="button" disabled={saving} onClick={onCreate}>
                  {saving ? "Creating…" : "Create link"}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
};
