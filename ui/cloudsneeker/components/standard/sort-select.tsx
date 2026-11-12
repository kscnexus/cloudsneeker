"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { STANDARD_PARAM } from "@/cloudsneeker/lib/standard-list";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";

export interface SortOption {
  value: string;
  label: string;
}

interface SortSelectProps {
  value: string;
  options: SortOption[];
  /** Sort the page uses when `sort` is not in the URL. */
  defaultValue?: string;
}

/** Table sort for lists whose columns do not sort on their own: sets the
 * `sort` URL parameter and returns to page 1. */
export const SortSelect = ({
  value,
  options,
  defaultValue,
}: SortSelectProps) => {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const onChange = (next: string) => {
    const params = new URLSearchParams(searchParams.toString());
    if (next && next !== defaultValue) params.set(STANDARD_PARAM.SORT, next);
    else params.delete(STANDARD_PARAM.SORT);
    params.delete(STANDARD_PARAM.PAGE);
    const query = params.toString();
    router.push(query ? `${pathname}?${query}` : pathname, { scroll: false });
  };

  return (
    <div className="flex items-center gap-2">
      <span className="text-text-neutral-secondary text-xs font-medium whitespace-nowrap">
        Sort by
      </span>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger aria-label="Sort by" className="h-9 w-44">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {options.map((option) => (
            <SelectItem key={option.value} value={option.value}>
              {option.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
};
