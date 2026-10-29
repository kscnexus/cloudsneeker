"use client";

import Link from "next/link";
import { useState } from "react";

import {
  downloadTextFile,
  resourcesToCsv,
  resourcesToJson,
} from "@/cloudsneeker/lib/custodian-export";
import type { CustodianMatchedResource } from "@/cloudsneeker/lib/custodian-resources";
import { findingsHrefForChecks } from "@/cloudsneeker/lib/custodian-templates";
import type { CustodianRunDelta } from "@/cloudsneeker/types/custodian";
import { Button } from "@/components/shadcn";
import { Badge } from "@/components/shadcn/badge/badge";
import { CodeSnippet } from "@/components/shadcn/code-snippet/code-snippet";
import { EntityInfo } from "@/components/shadcn/entities/entity-info";
import { InfoField } from "@/components/shadcn/info-field/info-field";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/shadcn/sheet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/shadcn/table/table";
import type { ProviderType } from "@/types/providers";

interface CustodianRunResourcesTableProps {
  resources: CustodianMatchedResource[];
  providerType?: string;
  delta?: CustodianRunDelta;
  prowlerCheckIds?: string[];
  runId?: string;
}

const DETAIL_KEYS = [
  "uid",
  "name",
  "type",
  "service",
  "region",
  "status",
  "policyName",
] as const;

export const CustodianRunResourcesTable = ({
  resources,
  providerType,
  delta,
  prowlerCheckIds = [],
  runId = "run",
}: CustodianRunResourcesTableProps) => {
  const [selected, setSelected] = useState<CustodianMatchedResource | null>(
    null,
  );
  const cloudProvider = (providerType || undefined) as ProviderType | undefined;
  const findingsHref = findingsHrefForChecks(prowlerCheckIds);
  const deltaByUid = new Map<string, string>();
  for (const uid of delta?.new ?? []) deltaByUid.set(uid, "new");
  for (const uid of delta?.gone ?? []) deltaByUid.set(uid, "gone");
  for (const uid of delta?.still_matched ?? []) {
    if (!deltaByUid.has(uid)) deltaByUid.set(uid, "still");
  }

  if (resources.length === 0) {
    return (
      <p className="text-text-neutral-secondary text-sm">
        No resources matched this dry-run.
      </p>
    );
  }

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() =>
            downloadTextFile(
              `governance-${runId}.csv`,
              resourcesToCsv(resources),
              "text/csv",
            )
          }
        >
          Export CSV
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() =>
            downloadTextFile(
              `governance-${runId}.json`,
              resourcesToJson(resources),
              "application/json",
            )
          }
        >
          Export JSON
        </Button>
        {findingsHref ? (
          <Button asChild variant="ghost" size="sm">
            <Link href={findingsHref}>Open related Findings</Link>
          </Button>
        ) : null}
        {delta ? (
          <span className="text-text-neutral-secondary text-xs">
            Delta: {delta.new_count ?? 0} new · {delta.gone_count ?? 0} gone ·{" "}
            {delta.still_matched_count ?? 0} still matched
          </span>
        ) : null}
      </div>

      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Resource</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Region</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Delta</TableHead>
            <TableHead>Policy</TableHead>
            <TableHead className="w-24">Details</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {resources.map((resource) => (
            <TableRow key={resource.id}>
              <TableCell>
                <EntityInfo
                  cloudProvider={cloudProvider}
                  entityAlias={resource.name}
                  entityId={resource.uid}
                  idLabel="UID"
                />
              </TableCell>
              <TableCell>
                <div className="flex flex-col gap-0.5 text-sm">
                  <span className="text-text-neutral-primary">
                    {resource.type}
                  </span>
                  <span className="text-text-neutral-secondary text-xs">
                    {resource.service}
                  </span>
                </div>
              </TableCell>
              <TableCell className="text-sm">{resource.region}</TableCell>
              <TableCell>
                <Badge variant="tag" className="capitalize">
                  {resource.status}
                </Badge>
              </TableCell>
              <TableCell>
                <Badge variant="tag" className="capitalize">
                  {deltaByUid.get(resource.uid) ?? "matched"}
                </Badge>
              </TableCell>
              <TableCell className="text-sm">{resource.policyName}</TableCell>
              <TableCell>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setSelected(resource)}
                >
                  View
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      <Sheet
        open={selected !== null}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-lg">
          {selected ? (
            <>
              <SheetHeader>
                <SheetTitle>{selected.name}</SheetTitle>
                <SheetDescription>
                  Matched governance resource details (dry-run only).
                </SheetDescription>
              </SheetHeader>
              <div className="mt-6 flex flex-col gap-4">
                {DETAIL_KEYS.map((key) => (
                  <InfoField key={key} label={key} variant="compact">
                    <span className="text-text-neutral-primary break-all text-sm">
                      {selected[key]}
                    </span>
                  </InfoField>
                ))}
                {Object.keys(selected.tags).length > 0 ? (
                  <InfoField label="tags" variant="compact">
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(selected.tags).map(([key, value]) => (
                        <Badge key={key} variant="tag">
                          {key}={value}
                        </Badge>
                      ))}
                    </div>
                  </InfoField>
                ) : null}
                <InfoField label="raw resource" variant="compact">
                  <CodeSnippet
                    value={JSON.stringify(selected.raw, null, 2)}
                    multiline
                    className="max-h-80 overflow-auto text-xs"
                  />
                </InfoField>
              </div>
            </>
          ) : null}
        </SheetContent>
      </Sheet>
    </>
  );
};
