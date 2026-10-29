import { permanentRedirect } from "next/navigation";

import { legacyRedirectHref } from "@/cloudsneeker/routes";
import type { SearchParamsProps } from "@/types";

interface LegacyGovernancePageProps {
  params: Promise<{ path?: string[] }>;
  searchParams: Promise<SearchParamsProps>;
}

// Old engine-named links keep working: /custodian/<rest> -> /governance/<rest>.
export default async function LegacyGovernancePage({
  params,
  searchParams,
}: LegacyGovernancePageProps) {
  const [{ path = [] }, query] = await Promise.all([params, searchParams]);
  permanentRedirect(legacyRedirectHref("/custodian", path, query));
}
