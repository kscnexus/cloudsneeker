import { ShieldCheck } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { BRAND } from "@/cloudsneeker/brand";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { OperatorNav } from "@/cloudsneeker/components/operator-nav";
import type { OperatorMeAttributes } from "@/cloudsneeker/types/operator";
import { Badge, Button } from "@/components/shadcn";

const ROLE_LABEL: Record<string, string> = {
  owner: "Owner",
  billing: "Billing",
  support: "Support",
  read_only: "Read only",
};

interface OperatorShellProps {
  me: OperatorMeAttributes;
  children: ReactNode;
}

/** Operator console chrome: no tenant sidebar, its own header and nav. */
export const OperatorShell = ({ me, children }: OperatorShellProps) => (
  <div className="bg-bg-neutral-primary flex min-h-dvh flex-col">
    <header className="border-border-neutral-secondary border-b">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-3 px-4 py-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <ShieldCheck
            aria-hidden="true"
            className="text-button-tertiary size-5"
          />
          <div className="flex min-w-0 flex-col">
            <span className="text-text-neutral-primary truncate text-base font-semibold">
              {BRAND.name} operator console
            </span>
            <span className="text-text-neutral-tertiary truncate text-xs">
              {me.email}
            </span>
          </div>
          <Badge variant="tag">{ROLE_LABEL[me.role] ?? me.role}</Badge>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <OperatorNav />
          <Button asChild size="sm" variant="outline">
            <Link href="/">Back to app</Link>
          </Button>
        </div>
      </div>
    </header>
    <main className="mx-auto flex w-full max-w-7xl min-w-0 flex-1 flex-col gap-6 px-4 py-6">
      {children}
    </main>
  </div>
);

/** Shown to anyone without an active operator role (and when switched off). */
export const OperatorNotAvailable = () => (
  <main className="bg-bg-neutral-primary flex min-h-dvh items-center justify-center px-4">
    <EmptyState
      className="w-full max-w-md"
      title="Not available"
      description="This page does not exist or you do not have access to it."
      action={
        <Button asChild size="sm" variant="outline">
          <Link href="/">Go to the app</Link>
        </Button>
      }
    />
  </main>
);

/** Load-error state for operator pages (never shown as an empty list). */
export const OperatorLoadError = ({
  title,
  message,
  retryHref,
}: {
  title: string;
  message: string;
  retryHref: string;
}) => (
  <EmptyState
    title={title}
    description={message}
    action={
      <Button asChild size="sm" variant="outline">
        <Link href={retryHref}>Retry</Link>
      </Button>
    }
  />
);
