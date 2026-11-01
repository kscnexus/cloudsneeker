import { ShieldAlert, ShieldCheck } from "lucide-react";
import Link from "next/link";

import { auth } from "@/auth.config";
import { getMfaStatus } from "@/cloudsneeker/actions/mfa";
import { getSsoPolicy } from "@/cloudsneeker/actions/sso";
import { EmptyState } from "@/cloudsneeker/components/empty-state";
import { MfaSettings } from "@/cloudsneeker/components/mfa-settings";
import { PageHeader } from "@/cloudsneeker/components/page-header";
import { SsoPolicyCard } from "@/cloudsneeker/components/sso-policy-card";
import { responseResource } from "@/cloudsneeker/lib/operator";
import { PRODUCT_ROUTE } from "@/cloudsneeker/routes";
import type {
  MfaStatusResource,
  SsoPolicyResource,
} from "@/cloudsneeker/types/mfa";
import { Button } from "@/components/shadcn";
import { ContentLayout } from "@/components/shadcn/content-layout";

export default async function SecurityPage() {
  const [session, response] = await Promise.all([
    auth(),
    getMfaStatus().catch(() => null),
  ]);
  const status = responseResource<MfaStatusResource>(response);
  const canManageAccount = Boolean(session?.user?.permissions?.manage_account);
  const ssoPolicy = canManageAccount
    ? responseResource<SsoPolicyResource>(
        await getSsoPolicy().catch(() => null),
      )
    : null;

  return (
    <ContentLayout title="Security" icon={<ShieldCheck />}>
      <PageHeader description="Multi-factor authentication for your account and, for administrators, the organization's MFA requirement and single sign-on options." />
      {status ? (
        <div className="flex flex-col gap-6">
          <MfaSettings
            status={status.attributes}
            canManageAccount={canManageAccount}
          />
          {ssoPolicy ? <SsoPolicyCard policy={ssoPolicy.attributes} /> : null}
        </div>
      ) : (
        <EmptyState
          icon={<ShieldAlert />}
          title="Security settings unavailable"
          description="Your MFA settings could not be loaded. Try again in a moment."
          action={
            <Button asChild size="sm" variant="outline">
              <Link href={PRODUCT_ROUTE.SECURITY}>Retry</Link>
            </Button>
          }
        />
      )}
    </ContentLayout>
  );
}
