"use client";

import { KeyRound } from "lucide-react";
import { useState } from "react";

import { resetUserPassword } from "@/cloudsneeker/actions/operator";
import {
  isErrorResult,
  responseError,
  temporaryPasswordFromMeta,
} from "@/cloudsneeker/lib/operator";
import { Button } from "@/components/shadcn";
import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/shadcn/dialog";

import { FormAlert } from "./form-layout";

interface MemberPasswordResetDialogProps {
  tenantId: string;
  userId: string;
  email: string;
}

/**
 * "Reset password" for one member of a customer organization. After the
 * operator confirms, the API returns a one-time temporary password; it is
 * shown here once and discarded when the dialog closes.
 */
export const MemberPasswordResetDialog = ({
  tenantId,
  userId,
  email,
}: MemberPasswordResetDialogProps) => {
  const [open, setOpen] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [password, setPassword] = useState<string | null>(null);

  const onOpenChange = (next: boolean) => {
    setOpen(next);
    if (!next) {
      setPassword(null);
      setError(null);
    }
  };

  const onConfirm = async () => {
    setResetting(true);
    setError(null);
    const result = await resetUserPassword(tenantId, userId);
    setResetting(false);
    const temporary = temporaryPasswordFromMeta(result);
    if (isErrorResult(result) || !temporary) {
      setError(responseError(result, "The password could not be reset."));
      return;
    }
    setPassword(temporary);
  };

  return (
    <>
      <Button
        type="button"
        variant="outline"
        size="xs"
        onClick={() => onOpenChange(true)}
        aria-label={`Reset password for ${email}`}
      >
        <KeyRound aria-hidden="true" />
        Reset password
      </Button>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reset password</DialogTitle>
            <DialogDescription>
              {password
                ? `Temporary password for ${email}. It is shown only once.`
                : `Give ${email} a new temporary password?`}
            </DialogDescription>
          </DialogHeader>

          {password ? (
            <div className="flex flex-col gap-3">
              <CodeSnippet value={password} className="max-w-full" />
              <p className="text-text-neutral-secondary text-sm">
                Send it to the user over a trusted channel and ask them to
                change it in their profile after signing in. It will not be
                shown again.
              </p>
            </div>
          ) : (
            <ul className="text-text-neutral-secondary list-disc pl-5 text-sm">
              <li>The current password stops working at once.</li>
              <li>
                Their sessions end within 30 minutes and their sign-in lockout
                is cleared.
              </li>
              <li>
                The new password applies to every organization this user belongs
                to.
              </li>
            </ul>
          )}

          <FormAlert message={error} />

          <DialogFooter>
            {password ? (
              <Button type="button" onClick={() => onOpenChange(false)}>
                Done
              </Button>
            ) : (
              <>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => onOpenChange(false)}
                  disabled={resetting}
                >
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="destructive"
                  onClick={onConfirm}
                  disabled={resetting}
                >
                  {resetting ? "Resetting…" : "Reset password"}
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
};
