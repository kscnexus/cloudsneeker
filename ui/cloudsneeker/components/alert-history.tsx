import Link from "next/link";

import { AlertEventActions } from "@/cloudsneeker/components/alert-event-actions";
import {
  ListFilterBar,
  ListPager,
} from "@/cloudsneeker/components/list-filter-bar";
import { ALERT_AREA_OPTIONS } from "@/cloudsneeker/lib/alert-areas";
import {
  ALERT_EVENT_STATUS,
  ALERT_EVENT_STATUS_OPTIONS,
  type AlertEventItem,
  alertEventStatusLabel,
  alertLinkLabel,
  ALERTS_HISTORY_TAB,
  ALERTS_TAB_PARAM,
  severitySummary,
} from "@/cloudsneeker/lib/alert-history";
import { formatAuditTime } from "@/cloudsneeker/lib/audit-log";
import {
  LIST_PARAM,
  type ListFilters,
  type ListPagination,
} from "@/cloudsneeker/lib/list-filters";
import { Badge } from "@/components/shadcn/badge/badge";
import { Card, CardContent } from "@/components/shadcn/card/card";

const PATH = "/alerts";
const KEEP = { [ALERTS_TAB_PARAM]: ALERTS_HISTORY_TAB };

const STATUS_VARIANT = {
  [ALERT_EVENT_STATUS.OPEN]: "warning",
  [ALERT_EVENT_STATUS.ACKNOWLEDGED]: "info",
  [ALERT_EVENT_STATUS.RESOLVED]: "success",
  [ALERT_EVENT_STATUS.DISMISSED]: "outline",
} as const;

interface AlertHistoryProps {
  events: AlertEventItem[];
  filters: ListFilters;
  pagination: ListPagination;
  loadError: string | null;
}

const EventRow = ({ event }: { event: AlertEventItem }) => (
  <li className="border-border-neutral-secondary flex flex-col gap-3 border-b py-4 last:border-b-0 lg:flex-row lg:items-start lg:justify-between">
    <div className="flex min-w-0 flex-1 flex-col gap-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-text-neutral-primary font-medium break-words">
          {event.ruleName || "Deleted rule"}
        </span>
        <Badge variant={STATUS_VARIANT[event.status]}>
          {alertEventStatusLabel(event.status)}
        </Badge>
        {event.trigger === "daily" ? <Badge variant="tag">Daily</Badge> : null}
      </div>
      <p className="text-text-neutral-secondary text-xs">
        {formatAuditTime(event.insertedAt)} · {event.total} finding(s)
        {event.delivered ? " · notified" : " · not delivered"}
      </p>
      <div className="flex flex-wrap gap-2">
        {event.areas.map((area) => (
          <Badge key={area.area} variant="tag">
            {area.label}: {area.count}
          </Badge>
        ))}
      </div>
      {Object.keys(event.severityCounts).length > 0 ? (
        <p className="text-text-neutral-secondary text-xs">
          {severitySummary(event.severityCounts)}
        </p>
      ) : null}
      {event.links.length > 0 ? (
        <div className="flex flex-wrap gap-3 text-xs">
          {event.links.map((link) => (
            <Link
              key={link}
              href={link}
              className="text-button-tertiary underline-offset-2 hover:underline"
            >
              {alertLinkLabel(link)}
            </Link>
          ))}
        </div>
      ) : null}
      {event.statusChange.at ? (
        <p className="text-text-neutral-secondary text-xs">
          {alertEventStatusLabel(event.status)}
          {event.statusChange.by ? ` by ${event.statusChange.by}` : ""} on{" "}
          {formatAuditTime(event.statusChange.at)}
        </p>
      ) : null}
    </div>
    <div className="w-full lg:w-72">
      <AlertEventActions
        eventId={event.id}
        status={event.status}
        note={event.note}
      />
    </div>
  </li>
);

/** Alert history: every firing of a rule, newest first, with its status. */
export const AlertHistory = ({
  events,
  filters,
  pagination,
  loadError,
}: AlertHistoryProps) => (
  <Card variant="base" padding="lg">
    <CardContent className="flex flex-col gap-4">
      <div>
        <h2 className="text-text-neutral-primary text-base font-medium">
          Alert history
        </h2>
        <p className="text-text-neutral-secondary text-sm">
          Each time a rule matched findings after a scan, a policy run or the
          daily check. Acknowledge, resolve or dismiss alerts as you work them.
        </p>
      </div>
      <ListFilterBar
        path={PATH}
        keep={KEEP}
        filters={filters}
        searchPlaceholder="Rule name"
        selects={[
          {
            name: LIST_PARAM.STATUS,
            label: "Status",
            allLabel: "All statuses",
            options: [...ALERT_EVENT_STATUS_OPTIONS],
          },
          {
            name: LIST_PARAM.TYPE,
            label: "Module",
            allLabel: "All modules",
            options: [...ALERT_AREA_OPTIONS],
          },
        ]}
      />
      {loadError ? (
        <p role="alert" className="text-text-error-primary text-sm">
          Alert history could not be loaded. {loadError}
        </p>
      ) : events.length === 0 ? (
        <p className="text-text-neutral-secondary text-sm">
          No alerts yet. An alert appears here when a rule matches findings.
        </p>
      ) : (
        <ul aria-label="Alert history">
          {events.map((event) => (
            <EventRow key={event.id} event={event} />
          ))}
        </ul>
      )}
      <ListPager
        path={PATH}
        keep={KEEP}
        filters={filters}
        pagination={pagination}
        noun="alerts"
      />
    </CardContent>
  </Card>
);
