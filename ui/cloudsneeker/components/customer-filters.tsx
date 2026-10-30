import Link from "next/link";

import { SUBSCRIPTION_STATUS_LABEL } from "@/cloudsneeker/lib/entitlements";
import type { CustomerFilters as CustomerFilterValues } from "@/cloudsneeker/lib/operator";
import {
  FORM_CHECK_CLASS,
  FORM_CHOICE_CLASS,
  FORM_SELECT_CLASS,
} from "@/cloudsneeker/lib/ui-classes";
import { OPERATOR_ROUTE } from "@/cloudsneeker/routes";
import type { PlanRef } from "@/cloudsneeker/types/operator";
import { Button, Input, Label } from "@/components/shadcn";

const SORT_OPTIONS = [
  { value: "name", label: "Name" },
  { value: "ends_at", label: "End date" },
  { value: "-last_activity", label: "Recent activity" },
  { value: "-inserted_at", label: "Newest" },
  { value: "plan", label: "Plan" },
  { value: "status", label: "Status" },
] as const;

interface CustomerFiltersProps {
  filters: CustomerFilterValues;
  plans: PlanRef[];
}

/** Plain GET form so filters live in the URL and work without scripts. */
export const CustomerFilters = ({ filters, plans }: CustomerFiltersProps) => (
  <form
    method="get"
    action={OPERATOR_ROUTE.CUSTOMERS}
    className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-6 lg:items-end"
    aria-label="Filter customers"
  >
    <div className="flex flex-col gap-1.5 lg:col-span-2">
      <Label htmlFor="customer-search">Search</Label>
      <Input
        id="customer-search"
        name="search"
        defaultValue={filters.search}
        placeholder="Name, tenant id or customer id"
      />
    </div>
    <div className="flex flex-col gap-1.5">
      <Label htmlFor="customer-status">Status</Label>
      <select
        id="customer-status"
        name="status"
        defaultValue={filters.status}
        className={FORM_SELECT_CLASS}
      >
        <option value="">Any status</option>
        {Object.entries(SUBSCRIPTION_STATUS_LABEL).map(([value, label]) => (
          <option key={value} value={value}>
            {label}
          </option>
        ))}
      </select>
    </div>
    <div className="flex flex-col gap-1.5">
      <Label htmlFor="customer-plan">Plan</Label>
      <select
        id="customer-plan"
        name="plan"
        defaultValue={filters.plan}
        className={FORM_SELECT_CLASS}
      >
        <option value="">Any plan</option>
        {plans.map((plan) => (
          <option key={plan.code} value={plan.code}>
            {plan.name}
          </option>
        ))}
      </select>
    </div>
    <div className="flex flex-col gap-1.5">
      <Label htmlFor="customer-sort">Sort</Label>
      <select
        id="customer-sort"
        name="sort"
        defaultValue={filters.sort}
        className={FORM_SELECT_CLASS}
      >
        {SORT_OPTIONS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
    <div className="flex flex-col gap-1.5">
      <Label htmlFor="customer-expiring">Ends within (days)</Label>
      <Input
        id="customer-expiring"
        name="expiring"
        inputMode="numeric"
        defaultValue={filters.expiring}
        placeholder="30"
      />
    </div>
    <label className={FORM_CHOICE_CLASS}>
      <input
        type="checkbox"
        name="over_limit"
        value="true"
        defaultChecked={filters.overLimit}
        className={FORM_CHECK_CLASS}
      />
      Over a limit only
    </label>
    <div className="flex gap-2 lg:col-span-5 lg:justify-end">
      <Button asChild size="sm" variant="outline">
        <Link href={OPERATOR_ROUTE.CUSTOMERS}>Clear</Link>
      </Button>
      <Button type="submit" size="sm">
        Apply
      </Button>
    </div>
  </form>
);
