import type { ReactNode } from "react";

import { Card } from "@/components/shadcn/card/card";
import { cn } from "@/lib/utils";

interface SectionCardProps {
  title: string;
  description?: ReactNode;
  /** Controls aligned with the title (links, buttons, filters). */
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  contentClassName?: string;
}

export const SectionCard = ({
  title,
  description,
  actions,
  children,
  className,
  contentClassName,
}: SectionCardProps) => (
  <Card
    variant="base"
    padding="none"
    role="region"
    aria-label={title}
    data-slot="section-card"
    className={cn("min-w-0 gap-0 shadow-sm", className)}
  >
    <div className="border-border-neutral-secondary flex flex-wrap items-start justify-between gap-3 border-b px-4 py-3 sm:px-5">
      <div className="flex min-w-0 flex-col gap-0.5">
        <h2 className="text-text-neutral-primary text-base font-semibold">
          {title}
        </h2>
        {description ? (
          <p className="text-text-neutral-tertiary text-sm">{description}</p>
        ) : null}
      </div>
      {actions ? (
        <div className="flex flex-wrap items-center gap-2">{actions}</div>
      ) : null}
    </div>
    <div className={cn("flex min-w-0 flex-col gap-3 p-4 sm:p-5", contentClassName)}>
      {children}
    </div>
  </Card>
);
