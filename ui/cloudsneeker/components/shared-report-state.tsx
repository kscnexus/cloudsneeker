import { Clock, Link2Off, SearchX, ServerCrash } from "lucide-react";
import type { ReactNode } from "react";

import { BrandWordmark } from "@/cloudsneeker/brand-logo";
import {
  SHARED_REPORT_STATUS,
  type SharedReportStatus,
} from "@/cloudsneeker/lib/shared-report";

type UnavailableStatus = Exclude<
  SharedReportStatus,
  typeof SHARED_REPORT_STATUS.OK
>;

const STATE_COPY: Record<
  UnavailableStatus,
  { title: string; body: string; icon: typeof Clock }
> = {
  [SHARED_REPORT_STATUS.EXPIRED]: {
    title: "This link has expired",
    body: "Shared report links stop working after their expiry date. Ask the person who shared it for a new link.",
    icon: Clock,
  },
  [SHARED_REPORT_STATUS.REVOKED]: {
    title: "This link was revoked",
    body: "The owner turned off access to this report. Ask them for a new link if you still need it.",
    icon: Link2Off,
  },
  [SHARED_REPORT_STATUS.NOT_FOUND]: {
    title: "Report not found",
    body: "Check that the link was copied completely.",
    icon: SearchX,
  },
  [SHARED_REPORT_STATUS.UNAVAILABLE]: {
    title: "Report unavailable",
    body: "The report could not be loaded right now. Try again in a few minutes.",
    icon: ServerCrash,
  },
};

export const SharedReportHeader = ({ children }: { children?: ReactNode }) => (
  <div className="flex flex-wrap items-center justify-between gap-3 print:pb-2">
    <BrandWordmark />
    <div className="flex items-center gap-3">
      <span className="text-text-neutral-tertiary text-xs">
        Shared report · read only
      </span>
      {children}
    </div>
  </div>
);

export const SharedReportState = ({ status }: { status: UnavailableStatus }) => {
  const copy = STATE_COPY[status];
  const Icon = copy.icon;
  return (
    <main className="mx-auto flex min-h-screen max-w-xl flex-col gap-10 px-4 py-10">
      <SharedReportHeader />
      <section
        role="status"
        data-state={status}
        className="border-border-neutral-secondary bg-bg-neutral-secondary flex flex-col items-center gap-3 rounded-xl border p-8 text-center"
      >
        <Icon aria-hidden="true" className="text-text-neutral-tertiary size-10" />
        <h1 className="text-text-neutral-primary text-xl font-semibold">
          {copy.title}
        </h1>
        <p className="text-text-neutral-secondary text-sm">{copy.body}</p>
      </section>
    </main>
  );
};
