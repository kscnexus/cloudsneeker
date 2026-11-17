"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  importConnectionRepositories,
  listConnectionRepositories,
} from "@/cloudsneeker/actions/appsec";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import { responseList } from "@/cloudsneeker/lib/findings-links";
import {
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import type {
  AppSecResource,
  SourceImportResult,
  SourceRepositoryAttributes,
} from "@/cloudsneeker/types/appsec";
import { Button, Input } from "@/components/shadcn";

export interface SourceConnectionSummary {
  id: string;
  label: string;
  repositoryCount: number;
}

interface SourceConnectionsPanelProps {
  connections: SourceConnectionSummary[];
  canManage: boolean;
}

const errorOf = (result: unknown): string | null => {
  if (!result || typeof result !== "object" || !("error" in result)) {
    return null;
  }
  const value = (result as { error?: unknown }).error;
  if (!value) return null;
  return typeof value === "string" ? value : "Request failed.";
};

const plural = (count: number, word: string) =>
  `${count} ${word}${count === 1 ? "" : "s"}`;

/** One GitHub connection: list its repositories and import the chosen ones. */
const ConnectionImport = ({
  connection,
  canManage,
}: {
  connection: SourceConnectionSummary;
  canManage: boolean;
}) => {
  const router = useRouter();
  const [repositories, setRepositories] = useState<
    SourceRepositoryAttributes[] | null
  >(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const load = async () => {
    setPending(true);
    setError(null);
    const result = await listConnectionRepositories(connection.id);
    setPending(false);
    const failure = errorOf(result);
    if (failure) {
      setError(failure);
      return;
    }
    const items = responseList<AppSecResource<SourceRepositoryAttributes>>(
      result,
    ).map((item) => item.attributes);
    setRepositories(items);
    setSelected(
      items
        .filter((item) => !item.already_added && !item.archived)
        .map((item) => item.clone_url),
    );
  };

  const onImport = async () => {
    setPending(true);
    setError(null);
    const result = await importConnectionRepositories(connection.id, selected);
    setPending(false);
    const failure = errorOf(result);
    if (failure) {
      setError(failure);
      return;
    }
    const summary = (result as { data?: { attributes?: SourceImportResult } })
      ?.data?.attributes;
    setMessage(
      summary
        ? `Added ${plural(summary.created.length, "repository")}${summary.linked.length ? `, linked ${summary.linked.length} already added` : ""}.`
        : "Repositories added.",
    );
    setRepositories(null);
    router.refresh();
  };

  const visible = (repositories ?? []).filter((item) =>
    item.full_name.toLowerCase().includes(query.trim().toLowerCase()),
  );
  const toggle = (url: string) =>
    setSelected((current) =>
      current.includes(url)
        ? current.filter((item) => item !== url)
        : [...current, url],
    );

  return (
    <SectionCard
      title={`GitHub · ${connection.label}`}
      description={`${plural(connection.repositoryCount, "repository")} imported. Imported repositories use this connection's token or GitHub App; no second token is needed.`}
    >
      {message ? (
        <p className="text-text-neutral-secondary text-sm">{message}</p>
      ) : null}
      {error ? (
        <p className="text-text-error-primary text-sm" role="alert">
          {error}
        </p>
      ) : null}
      {repositories === null ? (
        <div>
          <Button
            type="button"
            size="sm"
            disabled={!canManage || pending}
            onClick={() => void load()}
          >
            {pending ? "Listing…" : "Import repositories"}
          </Button>
          {!canManage ? (
            <p className="text-text-neutral-tertiary mt-2 text-xs">
              Importing needs the Manage providers permission.
            </p>
          ) : null}
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          <label htmlFor={`source-search-${connection.id}`} className="sr-only">
            Search repositories
          </label>
          <Input
            id={`source-search-${connection.id}`}
            placeholder="Search repositories"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <ul className="flex max-h-96 flex-col gap-1 overflow-y-auto">
            {visible.map((item) => (
              <li key={item.clone_url}>
                <label
                  htmlFor={`source-${item.clone_url}`}
                  className={FORM_CHOICE_CLASS}
                >
                  <input
                    id={`source-${item.clone_url}`}
                    type="checkbox"
                    className={FORM_CHECK_CLASS}
                    disabled={item.already_added}
                    checked={
                      item.already_added || selected.includes(item.clone_url)
                    }
                    onChange={() => toggle(item.clone_url)}
                  />
                  <span className="flex min-w-0 flex-col">
                    {item.full_name}
                    <span className="text-text-neutral-tertiary text-xs">
                      {[
                        item.private ? "Private" : "Public",
                        item.archived ? "Archived" : "",
                        item.already_added ? "Already added" : "",
                      ]
                        .filter(Boolean)
                        .join(" · ")}
                    </span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
          <div className="flex gap-2">
            <Button
              type="button"
              size="sm"
              disabled={pending || selected.length === 0}
              onClick={() => void onImport()}
            >
              {pending
                ? "Importing…"
                : `Import ${plural(selected.length, "repository")}`}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => setRepositories(null)}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}
    </SectionCard>
  );
};

/** GitHub connections whose repositories can be imported as code sources. */
export const SourceConnectionsPanel = ({
  connections,
  canManage,
}: SourceConnectionsPanelProps) => {
  if (connections.length === 0) {
    return (
      <SectionCard title="No GitHub connection yet">
        <p className="text-text-neutral-secondary text-sm">
          Add a GitHub provider under Providers with a token or a GitHub App.
          Its repositories can then be imported here, using the same
          credentials.
        </p>
      </SectionCard>
    );
  }
  return (
    <div className="flex flex-col gap-6">
      {connections.map((connection) => (
        <ConnectionImport
          key={connection.id}
          connection={connection}
          canManage={canManage}
        />
      ))}
    </div>
  );
};
