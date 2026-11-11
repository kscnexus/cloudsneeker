import { Info } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/shadcn/button/button";
import { Card, CardContent } from "@/components/shadcn/card/card";

/** Shown instead of the framework grid when a scan has no compliance data
 * because building it failed after the scan finished. */
export const ComplianceUnavailable = () => (
  <Card variant="base" padding="lg">
    <CardContent>
      <div
        role="status"
        className="flex w-full flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
      >
        <div className="flex items-start gap-4">
          <Info className="text-text-neutral-secondary mt-1 h-5 w-5 shrink-0" />
          <div>
            <h2 className="text-text-neutral-primary mb-1 text-base font-medium">
              Compliance results are not available for this scan
            </h2>
            <p className="text-text-neutral-secondary text-sm">
              The scan finished, but building its compliance results failed.
              Choose another scan above, or run a new scan of this account.
            </p>
          </div>
        </div>
        <Button asChild variant="secondary" size="sm" className="shrink-0">
          <Link href="/scans">Go to Scans</Link>
        </Button>
      </div>
    </CardContent>
  </Card>
);
