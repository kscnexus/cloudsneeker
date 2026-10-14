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
            <Mail className="size-10 text-gray-700 dark:text-gray-200" />
            <div className="flex flex-col gap-1">
              <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
                Email
              </h4>
              <p className="text-xs text-nowrap text-gray-500 dark:text-gray-300">
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
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Configure a per-tenant SMTP host so Cloudsneeker can email confirmed
          alert recipients when a rule matches.
        </p>
      </CardContent>
    </Card>
  );
};
