import { ScanSearch } from "lucide-react";
import Link from "next/link";
import { Suspense } from "react";

import {
  listTrivyRuns,
  listTrivyTargets,
} from "@/cloudsneeker/actions/trivy";
import { BRAND } from "@/cloudsneeker/brand";
import { TrivyTargetList } from "@/cloudsneeker/components/trivy-target-list";
import {
  findingsHrefForScan,
  labelForTrivyMode,
} from "@/cloudsneeker/lib/trivy-modes";
import { appSecurityHref } from "@/cloudsneeker/routes";
import type {
  TrivyRunResource,
  TrivyTargetResource,
} from "@/cloudsneeker/types/trivy";
import { Button, Skeleton } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function TrivyPage() {
  return (
    <ContentLayout title={BRAND.appSecurityName} icon={<ScanSearch />}>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4">
        <p className="text-text-neutral-secondary max-w-2xl text-sm">
          Scan Infrastructure as Code, container images, code archives,
          repository dependencies, SBOMs, and Kubernetes clusters. Results land
          in Findings next to your cloud security results.
        </p>
        <Button asChild size="sm">
          <Link href={appSecurityHref("new")}>New target</Link>
        </Button>
      </div>
      <Suspense fallback={<Skeleton className="h-64 w-full rounded-xl" />}>
        <SSRTrivyWorkspace />
      </Suspense>
    </ContentLayout>
  );
}

const SSRTrivyWorkspace = async () => {
  const [targetsResponse, runsResponse] = await Promise.all([
    listTrivyTargets({ "page[size]": "100", sort: "-inserted_at" }),
    listTrivyRuns({ "page[size]": "20", sort: "-inserted_at" }),
  ]);
  const targets = (targetsResponse?.data ?? []) as TrivyTargetResource[];
  const runs = (runsResponse?.data ?? []) as TrivyRunResource[];

  return (
    <div className="flex flex-col gap-8">
      <section className="flex flex-col gap-3">
        <h2 className="text-text-neutral-primary text-base font-semibold">
          Targets
        </h2>
        <TrivyTargetList targets={targets} />
      </section>

      <section className="flex flex-col gap-3">
        <h2 className="text-text-neutral-primary text-base font-semibold">
          Recent runs
        </h2>
        {runs.length === 0 ? (
          <p className="text-text-neutral-secondary text-sm">
            No scans yet.
          </p>
        ) : (
          <ul className="divide-border-neutral-secondary border-border-neutral-secondary divide-y rounded-xl border">
            {runs.map((run) => {
              const scanId =
                run.attributes.scan_id || run.attributes.summary?.scan_id;
              return (
                <li key={run.id} className="flex flex-col gap-1 px-4 py-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <Link
                      href={appSecurityHref(
                        run.attributes.target_id,
                        "runs",
                        run.id,
                      )}
                      className="text-text-neutral-primary font-medium underline-offset-2 hover:underline"
                    >
                      {run.attributes.target_name || run.attributes.target_id}
                    </Link>
                    <span className="text-text-neutral-secondary text-xs uppercase">
                      {run.attributes.status}
                    </span>
                  </div>
                  <p className="text-text-neutral-secondary text-sm">
                    {labelForTrivyMode(
                      run.attributes.target_mode ||
                        run.attributes.summary?.mode ||
                        "",
                    )}{" "}
                    · {run.attributes.trigger}
                    {typeof run.attributes.summary?.finding_count === "number"
                      ? ` · ${run.attributes.summary.finding_count} findings`
                      : ""}
                  </p>
                  {scanId ? (
                    <Link
                      href={findingsHrefForScan(scanId)}
                      className="text-text-neutral-secondary text-xs underline"
                    >
                      Open findings
                    </Link>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </section>
    </div>
  );
};
