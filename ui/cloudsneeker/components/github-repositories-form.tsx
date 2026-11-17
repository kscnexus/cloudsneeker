"use client";

import Link from "next/link";
import { useState } from "react";

import {
  addGithubRepositories,
  listGithubRepositories,
} from "@/cloudsneeker/actions/github-repositories";
import {
  BITBUCKET_IMPORT_BATCH_SIZE,
  chunk,
} from "@/cloudsneeker/lib/bitbucket-import";
import {
  connectionLabel,
  defaultGithubSelection,
  filterGithubRepositories,
} from "@/cloudsneeker/lib/github-repositories";
import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import {
  BITBUCKET_IMPORT_STATUS,
  type BitbucketImportResult,
  type BitbucketImportStatus,
} from "@/cloudsneeker/types/bitbucket";
import type {
  GithubConnection,
  GithubRepositoryListing,
} from "@/cloudsneeker/types/github-repositories";
import {
  Alert,
  AlertDescription,
  Badge,
  Button,
  Checkbox,
  Input,
  Label,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";

interface ResultBadge {
  label: string;
  variant: "success" | "tag" | "error" | "warning";
}

const RESULT_BADGE: Record<BitbucketImportStatus, ResultBadge> = {
  [BITBUCKET_IMPORT_STATUS.ADDED]: { label: "Added", variant: "success" },
  [BITBUCKET_IMPORT_STATUS.EXISTS]: { label: "Already added", variant: "tag" },
  [BITBUCKET_IMPORT_STATUS.FAILED]: { label: "Failed", variant: "error" },
  [BITBUCKET_IMPORT_STATUS.SKIPPED]: { label: "Skipped", variant: "warning" },
};

interface ImportProgress {
  done: number;
  total: number;
}

interface GithubRepositoriesFormProps {
  connections: GithubConnection[];
}

/** Picks repositories of a GitHub connection and adds them as code sources. */
export const GithubRepositoriesForm = ({
  connections,
}: GithubRepositoriesFormProps) => {
  const [connectionId, setConnectionId] = useState(connections[0]?.id ?? "");
  const [listing, setListing] = useState<GithubRepositoryListing | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [results, setResults] = useState<Record<string, BitbucketImportResult>>(
    {},
  );
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [isListing, setIsListing] = useState(false);
  const [progress, setProgress] = useState<ImportProgress | null>(null);
  const [dailySchedule, setDailySchedule] = useState(true);

  if (connections.length === 0) {
    return (
      <Alert variant="warning">
        <AlertDescription>
          No GitHub connection yet. Add a GitHub provider for your organization
          or user on the{" "}
          <Link href="/providers" className="underline">
            providers page
          </Link>
          , then come back to pick its repositories.
        </AlertDescription>
      </Alert>
    );
  }

  const isImporting = progress !== null;
  const visible = listing
    ? filterGithubRepositories(listing.repositories, query)
    : [];
  const selectable = visible.filter(
    (repository) =>
      !repository.already_added && !results[repository.repository_url],
  );
  const allVisibleSelected =
    selectable.length > 0 &&
    selectable.every((repository) => selected.has(repository.repository_url));
  const resultList = Object.values(results);
  const addedCount = resultList.filter(
    (result) => result.status === BITBUCKET_IMPORT_STATUS.ADDED,
  ).length;
  const problemCount = resultList.filter(
    (result) =>
      result.status === BITBUCKET_IMPORT_STATUS.FAILED ||
      result.status === BITBUCKET_IMPORT_STATUS.SKIPPED,
  ).length;

  const onConnectionChange = (value: string) => {
    setConnectionId(value);
    setListing(null);
    setSelected(new Set());
    setResults({});
    setError("");
  };

  const onList = async () => {
    setIsListing(true);
    setError("");
    setResults({});
    try {
      const result = await listGithubRepositories(connectionId);
      if ("error" in result) {
        setListing(null);
        setError(result.error);
        return;
      }
      setListing(result);
      setSelected(defaultGithubSelection(result.repositories));
    } finally {
      setIsListing(false);
    }
  };

  const toggle = (repositoryUrl: string, checked: boolean) => {
    const next = new Set(selected);
    if (checked) next.add(repositoryUrl);
    else next.delete(repositoryUrl);
    setSelected(next);
  };

  const toggleAllVisible = (checked: boolean) => {
    const next = new Set(selected);
    for (const repository of selectable) {
      if (checked) next.add(repository.repository_url);
      else next.delete(repository.repository_url);
    }
    setSelected(next);
  };

  const onAdd = async () => {
    if (!listing) return;
    const chosen = listing.repositories
      .filter((repository) => selected.has(repository.repository_url))
      .map(({ full_name, repository_url }) => ({ full_name, repository_url }));
    const options = {
      dailySchedule,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
    };
    setError("");
    setProgress({ done: 0, total: chosen.length });
    const collected: Record<string, BitbucketImportResult> = { ...results };
    try {
      let done = 0;
      for (const batch of chunk(chosen, BITBUCKET_IMPORT_BATCH_SIZE)) {
        const outcome = await addGithubRepositories(batch, options);
        if ("error" in outcome) {
          setError(outcome.error);
          break;
        }
        for (const result of outcome) {
          collected[result.repositoryUrl] = result;
        }
        done += batch.length;
        setProgress({ done, total: chosen.length });
        setResults({ ...collected });
      }
      setSelected(new Set());
    } finally {
      setProgress(null);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end gap-3">
        <div className="flex w-full flex-col gap-1.5 md:w-80">
          <Label htmlFor="github-connection">GitHub connection</Label>
          <Select value={connectionId} onValueChange={onConnectionChange}>
            <SelectTrigger id="github-connection">
              <SelectValue placeholder="Choose a connection" />
            </SelectTrigger>
            <SelectContent>
              {connections.map((connection) => (
                <SelectItem key={connection.id} value={connection.id}>
                  {connectionLabel(connection)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Button
          type="button"
          onClick={onList}
          disabled={!connectionId || isListing || isImporting}
        >
          {isListing ? "Listing…" : "List repositories"}
        </Button>
      </div>

      {error && (
        <Alert variant="error">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {listing && (
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-text-neutral-secondary text-sm">
              {listing.repositories.length} repositories found
              {listing.truncated && " (showing the first 1,000)"}.{" "}
              {selected.size} selected.
            </p>
            <div className="w-full md:w-72">
              <Input
                aria-label="Filter repositories"
                placeholder="Filter by name"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </div>
          </div>

          {listing.repositories.length === 0 ? (
            <p className="text-text-neutral-tertiary text-sm">
              This connection cannot read any repositories. For a GitHub App,
              check which repositories the installation was given.
            </p>
          ) : (
            <div className="border-border-neutral-secondary overflow-x-auto rounded-lg border">
              <table className="w-full text-sm">
                <thead className="bg-bg-neutral-secondary text-left">
                  <tr>
                    <th className="w-10 p-3">
                      <Checkbox
                        size="sm"
                        aria-label="Select all shown repositories"
                        checked={allVisibleSelected}
                        disabled={selectable.length === 0 || isImporting}
                        onCheckedChange={(value) =>
                          toggleAllVisible(value === true)
                        }
                      />
                    </th>
                    <th className="p-3 font-medium">Repository</th>
                    <th className="p-3 font-medium">Default branch</th>
                    <th className="p-3 font-medium">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((repository) => {
                    const result = results[repository.repository_url];
                    const locked = repository.already_added || Boolean(result);
                    const badge = result
                      ? RESULT_BADGE[result.status]
                      : repository.already_added
                        ? RESULT_BADGE[BITBUCKET_IMPORT_STATUS.EXISTS]
                        : null;
                    return (
                      <tr
                        key={repository.repository_url}
                        className="border-border-neutral-secondary border-t"
                      >
                        <td className="p-3">
                          <Checkbox
                            size="sm"
                            aria-label={`Select ${repository.full_name}`}
                            checked={selected.has(repository.repository_url)}
                            disabled={locked || isImporting}
                            onCheckedChange={(value) =>
                              toggle(repository.repository_url, value === true)
                            }
                          />
                        </td>
                        <td className="p-3">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-medium">
                              {repository.full_name}
                            </span>
                            <Badge variant="outline" size="sm">
                              {repository.is_private ? "Private" : "Public"}
                            </Badge>
                            {repository.is_archived && (
                              <Badge variant="outline" size="sm">
                                Archived
                              </Badge>
                            )}
                          </div>
                        </td>
                        <td className="text-text-neutral-secondary p-3">
                          {repository.default_branch || "—"}
                        </td>
                        <td className="p-3">
                          {badge && (
                            <Badge variant={badge.variant} size="sm">
                              {badge.label}
                            </Badge>
                          )}
                          {result?.message && (
                            <p className="text-text-neutral-tertiary mt-1 text-xs">
                              {result.message}
                            </p>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          <div className="flex items-center gap-2">
            <Checkbox
              id="github-daily-schedule"
              size="sm"
              checked={dailySchedule}
              disabled={isImporting}
              onCheckedChange={(value) => setDailySchedule(value === true)}
            />
            <Label htmlFor="github-daily-schedule">
              Scan each added repository every day at 02:00
            </Label>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Button
              type="button"
              onClick={onAdd}
              disabled={selected.size === 0 || isImporting}
            >
              {progress
                ? `Adding ${progress.done} of ${progress.total}…`
                : `Add ${selected.size} ${selected.size === 1 ? "repository" : "repositories"}`}
            </Button>
            {addedCount > 0 && (
              <Button asChild variant="outline">
                <Link href={PRODUCT_ROUTE.APPLICATION_SECURITY}>
                  Go to Application Security
                </Link>
              </Button>
            )}
          </div>
        </div>
      )}

      {resultList.length > 0 && !isImporting && (
        <Alert variant={problemCount > 0 ? "warning" : "success"}>
          <AlertDescription>
            {addedCount} added, each with a code repository scan target.
            {problemCount > 0 && ` ${problemCount} not added; see the status.`}
            {addedCount > 0 &&
              " They store no token: scans use this GitHub connection. Connection checks have started."}
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
};
