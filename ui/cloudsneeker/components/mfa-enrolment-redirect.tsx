"use client";

import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";

import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";

/**
 * Sends members to the Security page while their organization requires MFA
 * and they have not set it up (EB-008). The API refuses their other requests
 * with `mfa_enrolment_required` until then.
 */
export const MfaEnrolmentRedirect = ({ required }: { required: boolean }) => {
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (required && pathname !== PRODUCT_ROUTE.SECURITY) {
      router.replace(PRODUCT_ROUTE.SECURITY);
    }
  }, [required, pathname, router]);

  return null;
};
