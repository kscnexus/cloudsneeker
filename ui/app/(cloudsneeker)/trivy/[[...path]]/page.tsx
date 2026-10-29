import { permanentRedirect } from "next/navigation";

import { legacyRedirectHref } from "@/cloudsneeker/routes";
import type { SearchParamsProps } from "@/types";

interface LegacyAppSecurityPageProps {
  params: Promise<{ path?: string[] }>;
  searchParams: Promise<SearchParamsProps>;
}

// Old links keep working: /trivy/<rest> -> /application-security/<rest>.
export default async function LegacyAppSecurityPage({
  params,
  searchParams,
}: LegacyAppSecurityPageProps) {
  const [{ path = [] }, query] = await Promise.all([params, searchParams]);
  permanentRedirect(legacyRedirectHref("/trivy", path, query));
}
