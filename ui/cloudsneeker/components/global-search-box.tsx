import { Search } from "lucide-react";

import {
  SEARCH_MAX_LENGTH,
  SEARCH_PARAM,
  SEARCH_PATH,
} from "@/cloudsneeker/lib/global-search";
import { Input } from "@/components/shadcn";
import { cn } from "@/lib/utils";

interface GlobalSearchBoxProps {
  defaultValue?: string;
  className?: string;
  autoFocus?: boolean;
}

/** Search every product area: a plain GET form to the search page. */
export const GlobalSearchBox = ({
  defaultValue = "",
  className,
  autoFocus = false,
}: GlobalSearchBoxProps) => (
  <form
    method="get"
    action={SEARCH_PATH}
    role="search"
    className={cn("relative w-full", className)}
  >
    <Search
      aria-hidden="true"
      className="text-text-neutral-tertiary pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2"
    />
    <Input
      type="search"
      name={SEARCH_PARAM}
      defaultValue={defaultValue}
      maxLength={SEARCH_MAX_LENGTH}
      placeholder="Search findings, accounts, targets, policies"
      aria-label="Search everything"
      autoFocus={autoFocus}
      className="h-9 pl-8"
    />
  </form>
);
