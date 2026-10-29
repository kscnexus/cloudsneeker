import { Shield } from "lucide-react";
import Link from "next/link";

import { governanceHref } from "@/cloudsneeker/routes";
import { Button } from "@/components/shadcn";

export const CustodianEmptyState = () => (
  <div className="border-border-neutral-secondary flex flex-col items-center gap-4 rounded-xl border border-dashed p-10 text-center">
    <div className="bg-button-primary/10 flex h-14 w-14 items-center justify-center rounded-full">
      <Shield className="text-button-primary h-7 w-7" aria-hidden="true" />
    </div>
    <div className="flex flex-col gap-1">
      <h3 className="text-text-neutral-primary text-lg font-semibold">
        No governance policies yet
      </h3>
      <p className="text-text-neutral-secondary max-w-md text-sm">
        Create a YAML governance policy and dry-run it against a connected AWS,
        Azure, GCP, or Kubernetes provider. Apply mode is not available.
      </p>
    </div>
    <Button asChild size="sm">
      <Link href={governanceHref("new")}>Create policy</Link>
    </Button>
  </div>
);
