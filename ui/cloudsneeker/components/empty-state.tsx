import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

interface EmptyStateProps {
  title: string;
  description?: ReactNode;
  icon?: ReactNode;
  /** Call to action, usually a button or link. */
  action?: ReactNode;
  className?: string;
}

export const EmptyState = ({
  title,
  description,
  icon,
  action,
  className,
}: EmptyStateProps) => (
  <div
    data-slot="empty-state"
    className={cn(
      "border-border-neutral-tertiary flex flex-col items-center gap-2 rounded-xl border border-dashed px-4 py-8 text-center",
      className,
    )}
  >
    {icon ? (
      <span
        aria-hidden="true"
        className="bg-bg-neutral-tertiary text-button-tertiary mb-1 flex size-11 items-center justify-center rounded-full [&_svg]:size-5"
      >
        {icon}
      </span>
    ) : null}
    <h3 className="text-text-neutral-primary text-base font-semibold">
      {title}
    </h3>
    {description ? (
      <p className="text-text-neutral-secondary max-w-md text-sm">
        {description}
      </p>
    ) : null}
    {action ? (
      <div className="mt-2 flex flex-wrap items-center justify-center gap-2">
        {action}
      </div>
    ) : null}
  </div>
);
