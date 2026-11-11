"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";

import type { SelectScanComplianceDataProps } from "@/components/compliance/compliance-header/scan-selector";
import { Button } from "@/components/shadcn";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";

import {
  complianceScope,
  newestScanOfAccount,
  newestScanOfType,
} from "./single-scan-scope";

interface ComplianceScopeSelectorsProps {
  scans: SelectScanComplianceDataProps["scans"];
  selectedScanId: string;
}

/** Scans of the selected account (all scans when none is selected). */
export const scansInScope = <T extends { id: string }>(
  scans: (T & SelectScanComplianceDataProps["scans"][number])[],
  selectedScanId: string,
): T[] => {
  const ids = new Set(complianceScope(scans, selectedScanId).scans);
  const inScope = scans.filter((scan) => ids.has(scan.id));
  return inScope.length > 0 ? inScope : scans;
};

/** Single Scan steps 1 and 2: provider, then account. The scan selector
 * that follows lists the account's scans; frameworks follow the scan. */
export const ComplianceScopeSelectors = ({
  scans,
  selectedScanId,
}: ComplianceScopeSelectorsProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const scope = complianceScope(scans, selectedScanId);

  const openScan = (scanId: string | null) => {
    if (!scanId || scanId === selectedScanId) return;
    const params = new URLSearchParams(searchParams);
    params.set("scanId", scanId);
    // Regions belong to the previous scan.
    params.delete("filter[region__in]");
    router.push(`?${params.toString()}`, { scroll: false });
  };

  return (
    <>
      <div className="flex w-full flex-col gap-1 sm:w-48">
        <span className="text-text-neutral-secondary text-xs font-medium">
          Provider
        </span>
        <Select
          value={scope.providerType ?? undefined}
          onValueChange={(type) => openScan(newestScanOfType(scans, type))}
        >
          <SelectTrigger aria-label="Provider" className="w-full">
            <SelectValue placeholder="Select a provider" />
          </SelectTrigger>
          <SelectContent>
            {scope.cloudProviders.length > 0 ? (
              <SelectGroup>
                <SelectLabel>Cloud providers</SelectLabel>
                {scope.cloudProviders.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectGroup>
            ) : null}
            {scope.cloudProviders.length > 0 &&
            scope.saasProviders.length > 0 ? (
              <SelectSeparator />
            ) : null}
            {scope.saasProviders.length > 0 ? (
              <SelectGroup>
                <SelectLabel>SaaS and identity</SelectLabel>
                {scope.saasProviders.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectGroup>
            ) : null}
          </SelectContent>
        </Select>
      </div>
      <div className="flex w-full flex-col gap-1 sm:w-64">
        <span className="text-text-neutral-secondary text-xs font-medium">
          Account
        </span>
        <Select
          value={scope.account ?? undefined}
          onValueChange={(account) =>
            openScan(newestScanOfAccount(scans, account))
          }
        >
          <SelectTrigger aria-label="Account" className="w-full">
            <SelectValue placeholder="Select an account" />
          </SelectTrigger>
          <SelectContent>
            {scope.accounts.map((option) => (
              <SelectItem key={option.value} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </>
  );
};

/** Start a scan from Single Scan (the configuration flow's last step). */
export const RunComplianceScanLink = () => (
  <Button asChild size="sm" variant="outline">
    <Link href="/scans">Run a new scan</Link>
  </Button>
);
