"use client";

import { ScanSearch } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  planScanAllRepositories,
  scanRepositoryBatch,
} from "@/cloudsneeker/actions/app-security-scan-all";
import {
  SCAN_ALL_BATCH_SIZE,
  type RepositoryScanItem,
  type RepositoryScanResult,
  summarizeScanResults,
} from "@/cloudsneeker/lib/app-security-scan-all";
import { chunk } from "@/cloudsneeker/lib/bitbucket-import";
import { Alert, AlertDescription, Button } from "@/components/shadcn";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/shadcn/dialog";

const WORD_PLURALS = { repository: "repositories", scan: "scans" } as const;

const plural = (count: number, word: keyof typeof WORD_PLURALS) =>
  `${count} ${count === 1 ? word : WORD_PLURALS[word]}`;

/**
 * Starts a code repository scan on every connected repository, creating a
 * code repository target first for each one that has none.
 */
export const ScanAllRepositoriesButton = () => {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [items, setItems] = useState<RepositoryScanItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<{
    done: number;
    total: number;
  } | null>(null);
  const [results, setResults] = useState<RepositoryScanResult[] | null>(null);

  const running = progress !== null && results === null;
  const toCreate = items?.filter((item) => !item.targetId).length ?? 0;

  const onOpen = async () => {
    setOpen(true);
    setLoading(true);
    setError(null);
    setItems(null);
    setResults(null);
    setProgress(null);
    const plan = await planScanAllRepositories();
    setLoading(false);
    if ("error" in plan) {
      setError(plan.error);
      return;
    }
    setItems(plan.items);
  };

  const onStart = async () => {
    if (!items) return;
    setError(null);
    setProgress({ done: 0, total: items.length });
    const collected: RepositoryScanResult[] = [];
    for (const batch of chunk(items, SCAN_ALL_BATCH_SIZE)) {
      const outcome = await scanRepositoryBatch(batch);
      if ("error" in outcome) {
        setError(outcome.error);
        break;
      }
      collected.push(...outcome);
      setProgress({ done: collected.length, total: items.length });
    }
    setResults(collected);
    router.refresh();
  };

  const onOpenChange = (next: boolean) => {
    // Closing mid-run would hide progress; the run itself keeps going.
    if (!next && running) return;
    setOpen(next);
  };

  const summary = results ? summarizeScanResults(results) : null;
  const failures = results?.filter((result) => !result.started) ?? [];

  return (
    <>
      <Button type="button" size="sm" variant="outline" onClick={onOpen}>
        <ScanSearch aria-hidden="true" />
        Scan all repositories
      </Button>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Scan all repositories</DialogTitle>
            <DialogDescription>
              Checks every connected repository for vulnerable dependencies,
              secrets, misconfigurations and licenses.
            </DialogDescription>
          </DialogHeader>

          <div className="flex flex-col gap-3 text-sm">
            {loading ? <p>Loading connected repositories…</p> : null}

            {items && items.length === 0 ? (
              <p>
                There are no connected repositories yet. Add them under
                Providers or through the Bitbucket import first.
              </p>
            ) : null}

            {items && items.length > 0 && !progress ? (
              <p>
                {`This will start a code scan on ${plural(items.length, "repository")}.`}
                {toCreate > 0
                  ? ` ${toCreate} of them get a new code repository target first.`
                  : ""}{" "}
                Scans queue up and run a few at a time, so large batches take a
                while to finish.
              </p>
            ) : null}

            {running && progress ? (
              <p role="status">
                {`Starting ${progress.done} of ${progress.total}…`}
              </p>
            ) : null}

            {summary ? (
              <Alert variant={summary.failed > 0 ? "warning" : "success"}>
                <AlertDescription>
                  {`${plural(summary.started, "scan")} started.`}
                  {summary.failed > 0
                    ? ` ${summary.failed} could not start.`
                    : " Results appear under Recent scans as each one finishes."}
                </AlertDescription>
              </Alert>
            ) : null}

            {failures.length > 0 ? (
              <ul className="flex max-h-48 flex-col gap-1 overflow-y-auto">
                {failures.map((failure) => (
                  <li key={failure.providerId}>
                    <span className="font-medium">{failure.name}</span>
                    {failure.message ? (
                      <span className="text-text-neutral-tertiary block text-xs">
                        {failure.message}
                      </span>
                    ) : null}
                  </li>
                ))}
              </ul>
            ) : null}

            {error ? (
              <Alert variant="error">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}
          </div>

          <DialogFooter>
            {items && items.length > 0 && !progress ? (
              <>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setOpen(false)}
                >
                  Cancel
                </Button>
                <Button type="button" onClick={onStart}>
                  {`Start ${plural(items.length, "scan")}`}
                </Button>
              </>
            ) : (
              <Button
                type="button"
                variant="outline"
                disabled={running}
                onClick={() => setOpen(false)}
              >
                Close
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
};
