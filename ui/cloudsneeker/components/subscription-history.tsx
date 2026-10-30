import { CARD_LIST_CLASS } from "@/cloudsneeker/lib/ui-classes";
import type {
  SubscriptionChange,
  SubscriptionEventResource,
} from "@/cloudsneeker/types/operator";

const FIELD_LABEL: Record<string, string> = {
  plan: "Plan",
  status: "Status",
  starts_at: "Starts",
  ends_at: "Ends",
  trial_ends_at: "Trial ends",
  seats: "Seats",
  feature_overrides: "Feature toggles",
  limit_overrides: "Limit overrides",
  billing_source: "Billing source",
  external_customer_id: "External customer id",
  notes: "Notes",
};

const ACTION_LABEL: Record<string, string> = {
  created: "Subscription created",
  updated: "Subscription changed",
  expired: "Subscription expired",
};

const valueText = (value: unknown): string => {
  if (value === null || value === undefined || value === "") return "none";
  if (typeof value === "string")
    return value.length > 10 && /^\d{4}-\d{2}-\d{2}T/.test(value)
      ? value.slice(0, 10)
      : value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  return "changed";
};

/** One readable line per changed field. Values of free text are never shown. */
export const describeChange = (
  field: string,
  change: SubscriptionChange,
): string => {
  const label = FIELD_LABEL[field] ?? field;
  if (change.changed && !("to" in change)) return `${label} changed`;
  if (typeof change.to === "object" && change.to !== null)
    return `${label} changed`;
  return `${label}: ${valueText(change.from)} to ${valueText(change.to)}`;
};

export const SubscriptionHistory = ({
  events,
}: {
  events: SubscriptionEventResource[];
}) => (
  <ol className={CARD_LIST_CLASS} aria-label="Subscription history">
    {events.map((event) => {
      const attributes = event.attributes;
      return (
        <li key={event.id} className="flex flex-col gap-1 px-4 py-3 text-sm">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-text-neutral-primary font-medium">
              {ACTION_LABEL[attributes.action] ?? attributes.action}
            </span>
            <time
              dateTime={attributes.inserted_at ?? undefined}
              className="text-text-neutral-tertiary text-xs"
            >
              {attributes.inserted_at
                ? new Date(attributes.inserted_at).toLocaleString("en-GB", {
                    timeZone: "UTC",
                  })
                : ""}
            </time>
          </div>
          <ul className="text-text-neutral-secondary flex flex-col gap-0.5 text-xs">
            {Object.entries(attributes.changes ?? {}).map(([field, change]) => (
              <li key={field}>{describeChange(field, change)}</li>
            ))}
          </ul>
          <span className="text-text-neutral-tertiary text-xs">
            {attributes.actor_email ||
              (attributes.source === "system" ? "System" : attributes.source)}
          </span>
        </li>
      );
    })}
  </ol>
);
