import Link from "next/link";

import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { StandardSeverityBadge } from "@/cloudsneeker/components/standard/standard-severity-badge";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import type { SearchGroupItem } from "@/cloudsneeker/lib/global-search";

interface GlobalSearchResultsProps {
  query: string;
  groups: SearchGroupItem[];
  loadError: string | null;
}

/** Search results grouped by kind; empty groups are listed last, collapsed. */
export const GlobalSearchResults = ({
  query,
  groups,
  loadError,
}: GlobalSearchResultsProps) => {
  if (loadError) {
    return (
      <p role="alert" className="text-text-error-primary text-sm">
        Search failed. {loadError}
      </p>
    );
  }
  const found = groups.filter((group) => group.count > 0);
  const empty = groups.filter((group) => group.count === 0);
  if (found.length === 0) {
    return (
      <EmptyState
        title={`Nothing matches “${query}”`}
        description="Search looks at finding titles, checks, rules, resources and IDs, account names and IDs, targets, applications, policies and alert rules."
      />
    );
  }
  return (
    <div className="flex flex-col gap-4">
      {found.map((group) => (
        <SectionCard
          key={group.kind}
          title={group.label}
          description={`${group.count} match(es)`}
          actions={
            group.count > group.hits.length ? (
              <Link
                href={group.moreHref}
                className="text-sm underline underline-offset-2"
              >
                See all {group.count}
              </Link>
            ) : undefined
          }
        >
          <ul className="divide-border-neutral-secondary divide-y">
            {group.hits.map((hit) => (
              <li
                key={hit.id}
                className="flex flex-wrap items-center gap-3 py-2"
              >
                {hit.severity ? (
                  <StandardSeverityBadge severity={hit.severity} />
                ) : null}
                <div className="flex min-w-0 flex-1 flex-col">
                  <Link
                    href={hit.href}
                    className="text-text-neutral-primary truncate text-sm font-medium hover:underline"
                  >
                    {hit.title}
                  </Link>
                  {hit.subtitle ? (
                    <span className="text-text-neutral-secondary truncate text-xs">
                      {hit.subtitle}
                    </span>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        </SectionCard>
      ))}
      {empty.length > 0 ? (
        <p className="text-text-neutral-secondary text-sm">
          No matches in: {empty.map((group) => group.label).join(", ")}.
        </p>
      ) : null}
    </div>
  );
};
