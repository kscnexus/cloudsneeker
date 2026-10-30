import Link from "next/link";

import {
  listOperatorTenants,
  listPlans,
} from "@/cloudsneeker/actions/operator";
import { CustomerFilters } from "@/cloudsneeker/components/customer-filters";
import { CustomerTable } from "@/cloudsneeker/components/customer-table";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { OperatorLoadError } from "@/cloudsneeker/components/operator-shell";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SectionCard } from "@/cloudsneeker/components/section-card";
import {
  isListResponse,
  responseCount,
  responseList,
} from "@/cloudsneeker/lib/findings-links";
import {
  customerListParams,
  customerPageHref,
  OPERATOR_PAGE_SIZE,
  parseCustomerFilters,
  responseError,
} from "@/cloudsneeker/lib/operator";
import { OPERATOR_ROUTE } from "@/cloudsneeker/routes";
import type {
  OperatorTenantResource,
  PlanResource,
} from "@/cloudsneeker/types/operator";
import { Button } from "@/components/shadcn";

interface CustomersPageProps {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}

export default async function OperatorCustomersPage({
  searchParams,
}: CustomersPageProps) {
  const filters = parseCustomerFilters(await searchParams);
  const [response, plansResponse] = await Promise.all([
    listOperatorTenants(customerListParams(filters)),
    listPlans(),
  ]);
  const plans = responseList<PlanResource>(plansResponse).map((plan) => ({
    code: plan.attributes.code,
    name: plan.attributes.name,
  }));

  return (
    <>
      <PageHeader
        title="Customers"
        description="Every organization with its plan, subscription status, end date, members, provider usage and last activity."
      />
      <SectionCard title="Customers">
        <CustomerFilters filters={filters} plans={plans} />
        <CustomerResults response={response} filters={filters} />
      </SectionCard>
    </>
  );
}

const CustomerResults = ({
  response,
  filters,
}: {
  response: unknown;
  filters: ReturnType<typeof parseCustomerFilters>;
}) => {
  if (!isListResponse(response)) {
    return (
      <OperatorLoadError
        title="Customers unavailable"
        message={responseError(response, "Customers could not be loaded.")}
        retryHref={customerPageHref(
          OPERATOR_ROUTE.CUSTOMERS,
          filters,
          filters.page,
        )}
      />
    );
  }
  const tenants = responseList<OperatorTenantResource>(response);
  const count = responseCount(response) ?? tenants.length;
  const pages = Math.max(1, Math.ceil(count / OPERATOR_PAGE_SIZE));

  if (tenants.length === 0) {
    return (
      <EmptyState
        title="No customers match"
        description="Change or clear the filters."
      />
    );
  }

  return (
    <>
      <CustomerTable tenants={tenants} />
      <nav
        aria-label="Customer pages"
        className="flex items-center justify-between gap-2 text-sm"
      >
        <span className="text-text-neutral-secondary">
          {count} customer(s) · page {filters.page} of {pages}
        </span>
        <div className="flex gap-2">
          {filters.page > 1 ? (
            <Button asChild size="sm" variant="outline">
              <Link
                href={customerPageHref(
                  OPERATOR_ROUTE.CUSTOMERS,
                  filters,
                  filters.page - 1,
                )}
              >
                Previous
              </Link>
            </Button>
          ) : null}
          {filters.page < pages ? (
            <Button asChild size="sm" variant="outline">
              <Link
                href={customerPageHref(
                  OPERATOR_ROUTE.CUSTOMERS,
                  filters,
                  filters.page + 1,
                )}
              >
                Next
              </Link>
            </Button>
          ) : null}
        </div>
      </nav>
    </>
  );
};
