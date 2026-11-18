"use client";

import { ChevronDown, SlidersHorizontal } from "lucide-react";
import { type ReactNode, useId, useState } from "react";

import { Button } from "@/components/shadcn";
import { cn } from "@/lib/utils";

interface MobileFiltersProps {
  children: ReactNode;
}

/**
 * On phones the filter bar folds behind one "Filters" button so the list is
 * on screen first; from 768px it is always shown and the button is hidden.
 */
export const MobileFilters = ({ children }: MobileFiltersProps) => {
  const [open, setOpen] = useState(false);
  const panelId = useId();

  return (
    <div className="flex flex-col gap-3">
      <Button
        type="button"
        variant="outline"
        size="sm"
        className="self-start md:hidden"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((value) => !value)}
      >
        <SlidersHorizontal aria-hidden="true" />
        Filters
        <ChevronDown
          aria-hidden="true"
          className={cn("transition-transform", open && "rotate-180")}
        />
      </Button>
      <div id={panelId} className={cn(open ? "block" : "hidden", "md:block")}>
        {children}
      </div>
    </div>
  );
};
