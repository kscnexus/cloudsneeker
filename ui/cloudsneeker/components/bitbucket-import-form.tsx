"use client";

import Link from "next/link";
import { useState } from "react";

import {
  importBitbucketRepositories,
  listBitbucketRepositories,
} from "@/cloudsneeker/actions/bitbucket";
import {
  BITBUCKET_IMPORT_BATCH_SIZE,
  chunk,
  defaultSelection,
  filterRepositories,
  parseManualRepositories,
} from "@/cloudsneeker/lib/bitbucket-import";
import {
  BITBUCKET_CLONE_METHOD,
  BITBUCKET_HOST,
  BITBUCKET_IMPORT_STATUS,
  type BitbucketCloneMethod,
  type BitbucketConnection,
  type BitbucketHost,
  type BitbucketImportRequest,
  type BitbucketImportResult,
  type BitbucketImportStatus,
  type BitbucketRepositoryListing,
  type BitbucketSshKey,
} from "@/cloudsneeker/types/bitbucket";
import {
  Alert,
  AlertDescription,
  Badge,
  Button,
  Checkbox,
  Input,
  Label,
  Textarea,
} from "@/components/shadcn";

const EMPTY_CONNECTION: BitbucketConnection = {
  host: BITBUCKET_HOST.CLOUD,
  workspace: "",
  accessToken: "",
  username: "",
  serverUrl: "",
};

const EMPTY_SSH_KEY: BitbucketSshKey = {
  privateKey: "",
  passphrase: "",
  knownHosts: "",
};

const CLONE_METHOD_LABEL: Record<BitbucketCloneMethod, string> = {
  [BITBUCKET_CLONE_METHOD.TOKEN]: "Access token",
  [BITBUCKET_CLONE_METHOD.SSH]: "SSH key",
};

const HOST_LABEL: Record<BitbucketHost, string> = {
  [BITBUCKET_HOST.CLOUD]: "Bitbucket Cloud",
  [BITBUCKET_HOST.SERVER]: "Bitbucket Data Center / Server",
};

const RESULT_BADGE: Record<
  BitbucketImportStatus,
  { label: string; variant: "success" | "tag" | "error" | "warning" }
> = {
  [BITBUCKET_IMPORT_STATUS.ADDED]: { label: "Added", variant: "success" },
  [BITBUCKET_IMPORT_STATUS.EXISTS]: { label: "Already added", variant: "tag" },
  [BITBUCKET_IMPORT_STATUS.FAILED]: { label: "Failed", variant: "error" },
  [BITBUCKET_IMPORT_STATUS.SKIPPED]: { label: "Skipped", variant: "warning" },
};

interface FieldProps {
  id: string;
  label: string;
  hint?: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  type?: string;
}

const Field = ({
  id,
  label,
  hint,
  value,
  onChange,
  placeholder,
  type = "text",
}: FieldProps) => (
  <div className="flex flex-col gap-1.5">
    <Label htmlFor={id}>{label}</Label>
    <Input
      id={id}
      type={type}
      value={value}
      placeholder={placeholder}
      autoComplete="off"
      autoCapitalize="off"
      spellCheck={false}
      onChange={(event) => onChange(event.target.value)}
    />
    {hint && <p className="text-text-neutral-tertiary text-xs">{hint}</p>}
  </div>
);

export const BitbucketImportForm = () => {
  const [connection, setConnection] = useState(EMPTY_CONNECTION);
  const [cloneMethod, setCloneMethod] = useState<BitbucketCloneMethod>(
    BITBUCKET_CLONE_METHOD.TOKEN,
  );
  const [sshKey, setSshKey] = useState(EMPTY_SSH_KEY);
  const [listing, setListing] = useState<BitbucketRepositoryListing | null>(
    null,
  );
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [manualText, setManualText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isListing, setIsListing] = useState(false);
  const [progress, setProgress] = useState<{
    done: number;
    total: number;
  } | null>(null);
  const [results, setResults] = useState<Record<string, BitbucketImportResult>>(
    {},
  );

  const isServer = connection.host === BITBUCKET_HOST.SERVER;
  const isImporting = progress !== null && progress.done < progress.total;
  const canList =
    connection.accessToken.trim() !== "" &&
    (isServer
      ? connection.serverUrl.trim() !== ""
      : connection.workspace.trim() !== "");

  const update = (field: keyof BitbucketConnection) => (value: string) =>
    setConnection((current) => ({ ...current, [field]: value }));
  const updateSshKey = (field: keyof BitbucketSshKey) => (value: string) =>
    setSshKey((current) => ({ ...current, [field]: value }));
  const usesSsh = cloneMethod === BITBUCKET_CLONE_METHOD.SSH;
  const hasCloneCredentials = !usesSsh || sshKey.privateKey.trim() !== "";

  const onList = async () => {
    setIsListing(true);
    setError(null);
    setResults({});
    setProgress(null);
    try {
      const result = await listBitbucketRepositories(connection);
      if ("error" in result) {
        setListing(null);
        setError(result.error);
        return;
      }
      setListing(result);
      setSelected(defaultSelection(result.repositories));
    } finally {
      setIsListing(false);
    }
  };

  const manual = parseManualRepositories(manualText, connection.workspace);

  const importRepositories = async (
    chosen: BitbucketImportRequest["repositories"],
    cloneUsername: string,
  ): Promise<boolean> => {
    setError(null);
    setProgress({ done: 0, total: chosen.length });
    let done = 0;
    for (const batch of chunk(chosen, BITBUCKET_IMPORT_BATCH_SIZE)) {
      const outcome = await importBitbucketRepositories({
        repositories: batch.map(({ repository_url, ssh_url, full_name }) => ({
          repository_url,
          ssh_url,
          full_name,
        })),
        cloneMethod,
        accessToken: connection.accessToken,
        cloneUsername,
        ...(usesSsh ? { sshKey } : {}),
      });
      if ("error" in outcome) {
        setError(outcome.error);
        setProgress(null);
        return false;
      }
      setResults((current) => {
        const next = { ...current };
        for (const result of outcome) next[result.repositoryUrl] = result;
        return next;
      });
      done += batch.length;
      setProgress({ done, total: chosen.length });
      const skipped = outcome.some(
        (result) => result.status === BITBUCKET_IMPORT_STATUS.SKIPPED,
      );
      if (skipped) {
        // The plan limit was reached; the rest would be skipped too.
        setProgress({ done: chosen.length, total: chosen.length });
        return false;
      }
    }
    return true;
  };

  const onImport = async () => {
    if (!listing) return;
    const chosen = listing.repositories.filter((repository) =>
      selected.has(repository.repository_url),
    );
    if (await importRepositories(chosen, listing.cloneUsername)) {
      setSelected(new Set());
    }
  };

  const onImportManual = async () => {
    await importRepositories(manual.repositories, "");
  };

  const toggle = (url: string, checked: boolean) =>
    setSelected((current) => {
      const next = new Set(current);
      if (checked) next.add(url);
      else next.delete(url);
      return next;
    });

  const visible = listing
    ? filterRepositories(listing.repositories, query)
    : [];
  const selectable = visible.filter(
    (repository) =>
      !repository.already_added && !results[repository.repository_url],
  );
  const allVisibleSelected =
    selectable.length > 0 &&
    selectable.every((repository) => selected.has(repository.repository_url));

  const toggleAllVisible = (checked: boolean) =>
    setSelected((current) => {
      const next = new Set(current);
      for (const repository of selectable) {
        if (checked) next.add(repository.repository_url);
        else next.delete(repository.repository_url);
      }
      return next;
    });

  const resultList = Object.values(results);
  const addedCount = resultList.filter(
    (result) => result.status === BITBUCKET_IMPORT_STATUS.ADDED,
  ).length;
  const problemCount = resultList.filter(
    (result) =>
      result.status === BITBUCKET_IMPORT_STATUS.FAILED ||
      result.status === BITBUCKET_IMPORT_STATUS.SKIPPED,
  ).length;

  return (
    <div className="flex flex-col gap-6">
      <div
        className="flex flex-wrap gap-2"
        role="group"
        aria-label="Bitbucket host"
      >
        {Object.values(BITBUCKET_HOST).map((host) => (
          <Button
            key={host}
            type="button"
            size="sm"
            variant={connection.host === host ? "default" : "outline"}
            aria-pressed={connection.host === host}
            onClick={() => {
              setConnection((current) => ({ ...current, host }));
              setListing(null);
              setError(null);
            }}
          >
            {HOST_LABEL[host]}
          </Button>
        ))}
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {isServer && (
          <Field
            id="bitbucket-server-url"
            label="Server URL"
            placeholder="https://git.example.com"
            hint="Must be reachable from the internet over HTTPS."
            value={connection.serverUrl}
            onChange={update("serverUrl")}
          />
        )}
        <Field
          id="bitbucket-workspace"
          label={isServer ? "Project key (optional)" : "Workspace ID"}
          placeholder={isServer ? "Leave empty for every repository" : "acme"}
          hint={
            isServer
              ? undefined
              : "The workspace slug from bitbucket.org/<workspace>."
          }
          value={connection.workspace}
          onChange={update("workspace")}
        />
        <Field
          id="bitbucket-token"
          label="Access token"
          type="password"
          hint={
            isServer
              ? "HTTP access token with Repository read permission."
              : "Workspace, project or repository access token with the Repositories: Read scope, or an API token."
          }
          value={connection.accessToken}
          onChange={update("accessToken")}
        />
        <Field
          id="bitbucket-username"
          label={
            isServer
              ? "Username (optional)"
              : "Atlassian account email (optional)"
          }
          hint={
            isServer
              ? "Only for a personal HTTP access token."
              : "Only for a personal API token. Leave empty for access tokens."
          }
          value={connection.username}
          onChange={update("username")}
        />
      </div>

      <div className="flex flex-col gap-3">
        <div
          className="flex flex-wrap items-center gap-2"
          role="group"
          aria-label="Clone repositories with"
        >
          <span className="text-text-neutral-secondary text-sm">
            Clone repositories with
          </span>
          {Object.values(BITBUCKET_CLONE_METHOD).map((method) => (
            <Button
              key={method}
              type="button"
              size="sm"
              variant={cloneMethod === method ? "default" : "outline"}
              aria-pressed={cloneMethod === method}
              disabled={isImporting}
              onClick={() => setCloneMethod(method)}
            >
              {CLONE_METHOD_LABEL[method]}
            </Button>
          ))}
        </div>
        {usesSsh && (
          <div className="grid gap-4 md:grid-cols-2">
            <div className="flex flex-col gap-1.5 md:col-span-2">
              <Label htmlFor="bitbucket-ssh-key">SSH private key</Label>
              <Textarea
                id="bitbucket-ssh-key"
                rows={4}
                spellCheck={false}
                autoComplete="off"
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                value={sshKey.privateKey}
                onChange={(event) =>
                  updateSshKey("privateKey")(event.target.value)
                }
              />
              <p className="text-text-neutral-tertiary text-xs">
                Add its public key to a Bitbucket account that can read these
                repositories, or to each repository as a read-only access key.
                Every picked repository is added with its SSH URL and this key.
              </p>
            </div>
            <Field
              id="bitbucket-ssh-passphrase"
              label="Key passphrase (PEM keys only)"
              type="password"
              value={sshKey.passphrase}
              onChange={updateSshKey("passphrase")}
            />
            {isServer && (
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="bitbucket-ssh-known-hosts">SSH host key</Label>
                <Textarea
                  id="bitbucket-ssh-known-hosts"
                  rows={2}
                  spellCheck={false}
                  placeholder="Output of ssh-keyscan -p 7999 git.example.com"
                  value={sshKey.knownHosts}
                  onChange={(event) =>
                    updateSshKey("knownHosts")(event.target.value)
                  }
                />
              </div>
            )}
            <div className="flex flex-col gap-1.5 md:col-span-2">
              <Label htmlFor="bitbucket-manual-repositories">
                Repositories (optional, no access token needed)
              </Label>
              <Textarea
                id="bitbucket-manual-repositories"
                rows={3}
                spellCheck={false}
                autoComplete="off"
                placeholder={"acme/web\ngit@bitbucket.org:acme/api.git"}
                value={manualText}
                onChange={(event) => setManualText(event.target.value)}
              />
              <p className="text-text-neutral-tertiary text-xs">
                One per line: workspace/repository, a repository name in the
                workspace above, a Bitbucket link or an SSH clone URL. Or list
                them with an access token below.
              </p>
              {manual.invalid.length > 0 && (
                <p className="text-text-error-primary text-xs">
                  Not understood: {manual.invalid.join(", ")}
                </p>
              )}
              <div>
                <Button
                  type="button"
                  variant="outline"
                  onClick={onImportManual}
                  disabled={
                    manual.repositories.length === 0 ||
                    isImporting ||
                    !hasCloneCredentials
                  }
                >
                  {`Add ${manual.repositories.length} typed ${manual.repositories.length === 1 ? "repository" : "repositories"}`}
                </Button>
              </div>
              {manual.repositories.some(
                (repository) => results[repository.repository_url],
              ) && (
                <ul className="flex flex-col gap-1 text-sm">
                  {manual.repositories.map((repository) => {
                    const result = results[repository.repository_url];
                    if (!result) return null;
                    const badge = RESULT_BADGE[result.status];
                    return (
                      <li
                        key={repository.repository_url}
                        className="flex flex-wrap items-center gap-2"
                      >
                        <span className="font-medium">
                          {repository.full_name}
                        </span>
                        <Badge variant={badge.variant} size="sm">
                          {badge.label}
                        </Badge>
                        {result.message && (
                          <span className="text-text-neutral-tertiary text-xs">
                            {result.message}
                          </span>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          </div>
        )}
      </div>

      <div>
        <Button
          type="button"
          onClick={onList}
          disabled={!canList || isListing || isImporting}
        >
          {isListing ? "Listing repositories…" : "List repositories"}
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
                placeholder="Filter by name or project"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </div>
          </div>

          {listing.repositories.length === 0 ? (
            <p className="text-text-neutral-tertiary text-sm">
              This token cannot read any repositories here.
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
                    <th className="p-3 font-medium">Project</th>
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
                          <div className="flex items-center gap-2">
                            <span className="font-medium">
                              {repository.full_name}
                            </span>
                            <Badge variant="outline" size="sm">
                              {repository.is_private ? "Private" : "Public"}
                            </Badge>
                          </div>
                        </td>
                        <td className="text-text-neutral-secondary p-3">
                          {repository.project || "—"}
                        </td>
                        <td className="p-3">
                          {badge && (
                            <Badge
                              variant={badge.variant}
                              size="sm"
                              title={result?.message}
                            >
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

          <div className="flex flex-wrap items-center gap-3">
            <Button
              type="button"
              onClick={onImport}
              disabled={
                selected.size === 0 || isImporting || !hasCloneCredentials
              }
            >
              {isImporting && progress
                ? `Adding ${progress.done} of ${progress.total}…`
                : `Add ${selected.size} ${selected.size === 1 ? "repository" : "repositories"}`}
            </Button>
            {addedCount > 0 && (
              <Button asChild variant="outline">
                <Link href="/providers">Go to providers</Link>
              </Button>
            )}
          </div>
        </div>
      )}

      {resultList.length > 0 && !isImporting && (
        <Alert variant={problemCount > 0 ? "warning" : "success"}>
          <AlertDescription>
            {addedCount} added as Infrastructure as Code providers.
            {problemCount > 0 && ` ${problemCount} not added; see the status.`}
            {addedCount > 0 && (
              <>
                {" Connection checks have started; scan them from the "}
                <Link href="/providers" className="underline">
                  providers page
                </Link>
                .
              </>
            )}
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
};
