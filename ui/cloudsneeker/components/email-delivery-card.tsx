"use client";

import { Mail, SettingsIcon } from "lucide-react";
import Link from "next/link";

import { Button, Card, CardContent, CardHeader } from "@/components/shadcn";

export const EmailDeliveryCard = () => {
  return (
    <Card variant="base" padding="lg">
      <CardHeader>
        <div className="flex w-full flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <Mail className="text-text-neutral-secondary size-10" />
            <div className="flex flex-col gap-1">
              <h4 className="text-text-neutral-primary text-lg font-bold">
                Email
              </h4>
              <p className="text-text-neutral-tertiary text-xs text-nowrap">
                Deliver alert notifications through your SMTP server.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 self-end sm:self-center">
            <Button asChild size="sm">
              <Link href="/integrations/email">
                <SettingsIcon size={14} />
                Manage
              </Link>
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-text-neutral-secondary text-sm">
          Configure a per-tenant SMTP host so Cloudsneeker can email confirmed
          alert recipients when a rule matches.
        </p>
      </CardContent>
    </Card>
  );
};
