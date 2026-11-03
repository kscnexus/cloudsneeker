"use client";

import { Check, ChevronDown, ChevronUp, Plus, Sparkles } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { installCustodianLibraryPolicies } from "@/cloudsneeker/actions/custodian-library";
import { FormAlert } from "@/cloudsneeker/components/form-layout";
import { ReportSeverityBadge } from "@/cloudsneeker/components/report-severity-badge";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  actionError,
  coveragePercent,
  EMPTY_LIBRARY_FILTERS,
  filterLibraryPolicies,
  generateHref,
  installMessage,
  LIBRARY_PROVIDER_LABEL,
  LIBRARY_PROVIDERS,
  LIBRARY_SEVERITIES,
  libraryHref,
  pendingStarterIds,
  readInstallResult,
  summarizeCoverage,
  type LibraryFilters,
} from "@/cloudsneeker/lib/custodian-library";
import { severityLabel } from "@/cloudsneeker/lib/report-view";
import {
  CARD_LIST_CLASS,
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
  FORM_SELECT_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import type {
  LibraryCategory,
  LibraryCoverageRow,
  LibraryPolicyAttributes,
  LibraryProvider,
} from "@/cloudsneeker/types/custodian-library";
import { Badge, Button, Input } from "@/components/shadcn";
import { cn } from "@/lib/utils";

interface ProviderOption {
  id: string;
  label: string;
}

interface CustodianLibraryBrowserProps {
  providerType: LibraryProvider;
  policies: LibraryPolicyAttributes[];
  categories: LibraryCategory[];
  coverage: LibraryCoverageRow[];
  providers: ProviderOption[];
}

export const CustodianLibraryBrowser = ({
  providerType,
  policies,
  categories,
  coverage,
  providers,
}: CustodianLibraryBrowserProps) => {
  const router = useRouter();
  const [filters, setFilters] = useState<LibraryFilters>(EMPTY_LIBRARY_FILTERS);
  const [providerId, setProviderId] = useState(providers[0]?.id ?? "");
  const [expanded, setExpanded] = useState<string[]>([]);
  const [busyIds, setBusyIds] = useState<string[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const visible = filterLibraryPolicies(policies, filters);
  const summary = summarizeCoverage(coverage, providerType);
  const starterIds = pendingStarterIds(policies);
  const providerName = LIBRARY_PROVIDER_LABEL[providerType];
  const canInstall = providers.length > 0 && Boolean(providerId);

  const updateFilters = (patch: Partial<LibraryFilters>) =>
    setFilters({ ...filters, ...patch });

  const install = async (policyIds: string[]) => {
    if (!canInstall || policyIds.length === 0) return;
    setBusyIds(policyIds);
    setMessage(null);
    setError(null);
    const response = await installCustodianLibraryPolicies({
      providerId,
      policyIds,
    });
    setBusyIds([]);
    const failure = actionError(response);
    if (failure) {
      setError(failure);
      return;
    }
    const result = readInstallResult(response);
    setMessage(result ? installMessage(result) : "Policies added.");
    router.refresh();
  };

  const toggle = (id: string) =>
    setExpanded(
      expanded.includes(id)
        ? expanded.filter((item) => item !== id)
        : [...expanded, id],
    );

  return (
    <div className="flex min-w-0 flex-col gap-6">
      <nav
        aria-label="Cloud"
        className="flex flex-wrap items-center justify-between gap-3"
      >
        <div className="flex flex-wrap gap-2">
          {LIBRARY_PROVIDERS.map((item) => (
            <Button
              key={item}
              asChild
              size="sm"
              variant={item === providerType ? "default" : "outline"}
            >
              <Link
                href={libraryHref(item)}
                aria-current={item === providerType ? "page" : undefined}
              >
                {LIBRARY_PROVIDER_LABEL[item]}
              </Link>
            </Button>
          ))}
        </div>
        <Button asChild size="sm" variant="outline">
          <Link href={generateHref()}>
            <Sparkles aria-hidden="true" />
            Generate with AI
          </Link>
        </Button>
      </nav>

      <SectionCard
        title={`${providerName} coverage`}
        description={`${summary.active} of ${summary.total} library policies active across ${summary.coveredCategories} of ${summary.rows.length} categories. Select a category to filter.`}
        actions={
          <Button
            size="sm"
            disabled={
              !canInstall || starterIds.length === 0 || busyIds.length > 0
            }
            onClick={() => install(starterIds)}
          >
            <Plus aria-hidden="true" />
            {starterIds.length === 0
              ? "Starter pack added"
              : `Add starter pack (${starterIds.length})`}
          </Button>
        }
      >
        <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {summary.rows.map((row) => {
            const selected = filters.category === row.category;
            const percent = coveragePercent(row.active, row.total);
            return (
              <li key={row.category}>
                <button
                  type="button"
                  aria-pressed={selected}
                  onClick={() =>
                    updateFilters({ category: selected ? "" : row.category })
                  }
                  className={cn(
                    "border-border-neutral-secondary hover:bg-bg-neutral-secondary flex w-full flex-col gap-2 rounded-lg border p-3 text-left",
                    selected && "border-button-tertiary",
                  )}
                >
                  <span className="text-text-neutral-primary text-sm font-medium">
                    {row.category_name}
                  </span>
                  <span className="text-text-neutral-tertiary text-xs">
                    {row.active} / {row.total} active
                  </span>
                  <span
                    className="bg-bg-neutral-tertiary h-1.5 w-full overflow-hidden rounded-full"
                    aria-hidden="true"
                  >
                    <span
                      className="bg-button-tertiary block h-full rounded-full"
                      style={{ width: `${percent}%` }}
                    />
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </SectionCard>

      <SectionCard
        title="Policy library"
        description="Dry-run policies written for common security, cost and hygiene rules. Adding one creates a policy you can edit, schedule and dry-run."
      >
        <div className="flex flex-col gap-4">
          <div className="grid gap-3 md:grid-cols-[2fr_1fr_1fr_1fr]">
            <Input
              aria-label="Search the library"
              placeholder="Search by name, resource or framework"
              value={filters.search}
              onChange={(event) =>
                updateFilters({ search: event.target.value })
              }
            />
            <select
              aria-label="Category"
              className={FORM_SELECT_CLASS}
              value={filters.category}
              onChange={(event) =>
                updateFilters({ category: event.target.value })
              }
            >
              <option value="">All categories</option>
              {categories.map((category) => (
                <option key={category.id} value={category.id}>
                  {category.name}
                </option>
              ))}
            </select>
            <select
              aria-label="Severity"
              className={FORM_SELECT_CLASS}
              value={filters.severity}
              onChange={(event) =>
                updateFilters({ severity: event.target.value })
              }
            >
              <option value="">All severities</option>
              {LIBRARY_SEVERITIES.map((severity) => (
                <option key={severity} value={severity}>
                  {severityLabel(severity)}
                </option>
              ))}
            </select>
            <select
              aria-label="Add to provider"
              className={FORM_SELECT_CLASS}
              value={providerId}
              disabled={providers.length === 0}
              onChange={(event) => setProviderId(event.target.value)}
            >
              {providers.length === 0 ? (
                <option value="">No {providerName} provider connected</option>
              ) : (
                providers.map((provider) => (
                  <option key={provider.id} value={provider.id}>
                    Add to {provider.label}
                  </option>
                ))
              )}
            </select>
          </div>
          <div className="flex flex-wrap gap-4">
            <label className={FORM_CHOICE_CLASS}>
              <input
                type="checkbox"
                className={FORM_CHECK_CLASS}
                checked={filters.starterOnly}
                onChange={(event) =>
                  updateFilters({ starterOnly: event.target.checked })
                }
              />
              <span>Recommended starter pack only</span>
            </label>
            <label className={FORM_CHOICE_CLASS}>
              <input
                type="checkbox"
                className={FORM_CHECK_CLASS}
                checked={filters.hideInstalled}
                onChange={(event) =>
                  updateFilters({ hideInstalled: event.target.checked })
                }
              />
              <span>Hide policies already added</span>
            </label>
          </div>

          <FormAlert message={error} />
          {message ? (
            <p role="status" className="text-text-success-primary text-sm">
              {message}
            </p>
          ) : null}

          <p className="text-text-neutral-tertiary text-xs">
            Showing {visible.length} of {policies.length} policies
          </p>

          {visible.length === 0 ? (
            <p className="text-text-neutral-secondary text-sm">
              No library policies match these filters.
            </p>
          ) : (
            <ul className={CARD_LIST_CLASS}>
              {visible.map((policy) => {
                const open = expanded.includes(policy.id);
                const busy = busyIds.includes(policy.id);
                return (
                  <li
                    key={policy.id}
                    className="flex flex-col gap-3 px-4 py-3"
                    data-testid="library-policy"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div className="flex min-w-0 flex-1 flex-col gap-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="text-text-neutral-primary font-medium">
                            {policy.name}
                          </span>
                          <ReportSeverityBadge severity={policy.severity} />
                          {policy.starter ? (
                            <Badge variant="outline">Starter</Badge>
                          ) : null}
                        </div>
                        <p className="text-text-neutral-secondary text-sm">
                          {policy.description}
                        </p>
                        <div className="text-text-neutral-tertiary flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
                          <span>{policy.category_name}</span>
                          <span className="font-mono">{policy.resource}</span>
                          {policy.frameworks.map((framework) => (
                            <Badge key={framework} variant="tag">
                              {framework}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      <div className="flex shrink-0 gap-2">
                        <Button
                          size="sm"
                          variant="ghost"
                          aria-expanded={open}
                          onClick={() => toggle(policy.id)}
                        >
                          {open ? (
                            <ChevronUp aria-hidden="true" />
                          ) : (
                            <ChevronDown aria-hidden="true" />
                          )}
                          YAML
                        </Button>
                        {policy.installed ? (
                          <Button size="sm" variant="outline" disabled>
                            <Check aria-hidden="true" />
                            Added
                          </Button>
                        ) : (
                          <Button
                            size="sm"
                            disabled={!canInstall || busyIds.length > 0}
                            onClick={() => install([policy.id])}
                          >
                            <Plus aria-hidden="true" />
                            {busy ? "Adding…" : "Add"}
                          </Button>
                        )}
                      </div>
                    </div>
                    {open ? (
                      <pre className="bg-bg-neutral-tertiary text-text-neutral-primary overflow-x-auto rounded-md p-3 font-mono text-xs">
                        {policy.policy_yaml}
                      </pre>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </SectionCard>
    </div>
  );
};
