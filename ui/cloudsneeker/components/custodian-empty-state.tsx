import { Shield } from "lucide-react";
import Link from "next/link";

import { governanceHref } from "@/cloudsneeker/routes";
import { Button } from "@/components/shadcn";

import { EmptyState } from "./empty-state";

export const CustodianEmptyState = () => (
  <EmptyState
    icon={<Shield />}
    title="No governance policies yet"
    description="Create a YAML governance policy and dry-run it against a connected AWS, Azure, GCP, or Kubernetes provider. Apply mode is not available."
    action={
      <Button asChild size="sm">
        <Link href={governanceHref("new")}>Create policy</Link>
      </Button>
    }
  />
);
