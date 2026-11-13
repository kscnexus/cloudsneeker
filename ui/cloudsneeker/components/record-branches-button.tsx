"use client";

import { GitBranch } from "lucide-react";
import { useState } from "react";

import { recordTargetBranches } from "@/cloudsneeker/actions/appsec";
import { recordBranchesMessage } from "@/cloudsneeker/lib/repository-branches";
import { Button } from "@/components/shadcn";

/**
 * Records the branch of repository and static analysis targets saved
 * without one, so every list and report names the branch they scan.
 */
export const RecordBranchesButton = () => {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const onClick = async () => {
    setBusy(true);
    setMessage(null);
    const result = await recordTargetBranches();
    setBusy(false);
    setMessage(recordBranchesMessage(result));
  };

  return (
    <div className="flex items-center gap-2">
      <Button
        type="button"
        variant="ghost"
        size="sm"
        onClick={onClick}
        disabled={busy}
        title="Add the scanned branch to targets that do not name one yet"
      >
        <GitBranch aria-hidden="true" />
        {busy ? "Recording…" : "Record branches"}
      </Button>
      {message ? (
        <span role="status" className="text-text-neutral-secondary text-xs">
          {message}
        </span>
      ) : null}
    </div>
  );
};
