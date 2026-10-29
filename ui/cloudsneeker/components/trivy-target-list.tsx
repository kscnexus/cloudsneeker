import Link from "next/link";

import { labelForTrivyMode } from "@/cloudsneeker/lib/trivy-modes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type { TrivyTargetResource } from "@/cloudsneeker/types/trivy";

interface TrivyTargetListProps {
  targets: TrivyTargetResource[];
}

export const TrivyTargetList = ({ targets }: TrivyTargetListProps) => {
  if (targets.length === 0) {
    return (
      <div className="border-border-neutral-secondary rounded-xl border px-4 py-8 text-center">
        <p className="text-text-neutral-primary mb-1 font-medium">
          No targets yet
        </p>
        <p className="text-text-neutral-secondary mb-4 text-sm">
          Add an Infrastructure as Code, container image, code archive,
          dependency, SBOM, or Kubernetes target. Results land in Findings next
          to your cloud security results.
        </p>
        <Link
          href={appSecurityHref("new")}
          className="text-text-neutral-primary text-sm underline"
        >
          Create a target
        </Link>
      </div>
    );
  }

  return (
    <ul className="divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-xl border">
      {targets.map((target) => (
        <li key={target.id}>
          <Link
            href={appSecurityHref(target.id)}
            className="hover:bg-bg-neutral-secondary flex flex-col gap-1 px-4 py-3"
          >
            <span className="text-text-neutral-primary font-medium">
              {target.attributes.name}
            </span>
            <span className="text-text-neutral-secondary text-sm">
              {labelForTrivyMode(target.attributes.mode)} ·{" "}
              {target.attributes.provider_alias ||
                target.attributes.provider_uid ||
                target.attributes.provider_id}
              {target.attributes.description
                ? ` — ${target.attributes.description}`
                : ""}
            </span>
            {target.attributes.schedule_enabled ? (
              <span className="text-text-neutral-secondary text-xs">
                Schedule: {target.attributes.schedule_cron} (
                {target.attributes.schedule_timezone || "UTC"})
              </span>
            ) : (
              <span className="text-text-neutral-secondary text-xs">
                Schedule: off
              </span>
            )}
          </Link>
        </li>
      ))}
    </ul>
  );
};
