import { ScanSearch } from "lucide-react";
import Link from "next/link";

import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { CARD_LIST_CLASS, FOCUS_RING_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type { TrivyTargetResource } from "@/cloudsneeker/types/trivy";
import { Badge, Button } from "@/components/shadcn";
import { cn } from "@/lib/utils";

import { EmptyState } from "./empty-state";

interface TrivyTargetListProps {
  targets: TrivyTargetResource[];
}

export const TrivyTargetList = ({ targets }: TrivyTargetListProps) => {
  if (targets.length === 0) {
    return (
      <EmptyState
        icon={<ScanSearch />}
        title="No targets yet"
        description="Add an Infrastructure as Code, container image, code archive, dependency, source code, SBOM, or Kubernetes target. Results land in Findings next to your cloud security results."
        action={
          <Button asChild size="sm">
            <Link href={appSecurityHref("new")}>Create a target</Link>
          </Button>
        }
      />
    );
  }

  return (
    <ul className={CARD_LIST_CLASS}>
      {targets.map((target) => (
        <li key={target.id}>
          <Link
            href={appSecurityHref(target.id)}
            className={cn(
              "hover:bg-bg-neutral-tertiary flex flex-col gap-1 px-4 py-3 transition-colors",
              FOCUS_RING_CLASS,
            )}
          >
            <span className="flex flex-wrap items-center gap-2">
              <span className="text-text-neutral-primary font-medium break-words">
                {target.attributes.name}
              </span>
              <Badge variant="tag">
                {labelForTrivyMode(target.attributes.mode)}
              </Badge>
            </span>
            <span className="text-text-neutral-secondary text-sm break-words">
              {target.attributes.provider_alias ||
                target.attributes.provider_uid ||
                target.attributes.provider_id}
              {target.attributes.description
                ? ` — ${target.attributes.description}`
                : ""}
            </span>
            <span className="text-text-neutral-tertiary text-xs">
              {target.attributes.schedule_enabled
                ? `Schedule: ${target.attributes.schedule_cron} (${target.attributes.schedule_timezone || "UTC"})`
                : "Schedule: off"}
            </span>
          </Link>
        </li>
      ))}
    </ul>
  );
};
