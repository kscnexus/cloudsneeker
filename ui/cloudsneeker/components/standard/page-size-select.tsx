"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";

import {
  PAGE_SIZE_OPTIONS,
  STANDARD_PARAM,
} from "@/cloudsneeker/lib/standard-list";

interface PageSizeSelectProps {
  value: number;
  options?: readonly number[];
}

/** "Rows per page", as in the Cloud Security Findings pagination: sets the
 * `pageSize` URL parameter and returns to page 1. */
export const PageSizeSelect = ({
  value,
  options = PAGE_SIZE_OPTIONS,
}: PageSizeSelectProps) => {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const choices = options.includes(value)
    ? options
    : [...options, value].sort((left, right) => left - right);

  const onChange = (next: string) => {
    const params = new URLSearchParams(searchParams.toString());
    params.set(STANDARD_PARAM.PAGE_SIZE, next);
    params.set(STANDARD_PARAM.PAGE, "1");
    router.push(`${pathname}?${params.toString()}`, { scroll: false });
  };

  return (
    <div className="flex items-center gap-3">
      <span className="text-text-neutral-secondary text-xs font-medium whitespace-nowrap">
        Rows per page
      </span>
      <Select value={String(value)} onValueChange={onChange}>
        <SelectTrigger
          iconSize="sm"
          aria-label="Rows per page"
          className="bg-bg-neutral-tertiary border-border-neutral-tertiary !h-auto !w-auto !min-w-0 !gap-1 !rounded-full !px-[19px] !py-[9px] !text-xs !font-medium"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent side="top">
          {choices.map((size) => (
            <SelectItem
              key={size}
              value={String(size)}
              className="cursor-pointer"
            >
              {size}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
};
