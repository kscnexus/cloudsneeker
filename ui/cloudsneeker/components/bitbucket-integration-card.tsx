"use client";

import { FolderGit2, SettingsIcon } from "lucide-react";
import Link from "next/link";

import { BITBUCKET_IMPORT_ROUTE } from "@/cloudsneeker/routes";
import { Button, Card, CardContent, CardHeader } from "@/components/shadcn";

export const BitbucketIntegrationCard = () => {
  return (
    <Card variant="base" padding="lg">
      <CardHeader>
        <div className="flex w-full flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <FolderGit2 className="size-10 text-gray-700 dark:text-gray-200" />
            <div className="flex flex-col gap-1">
              <h4 className="text-lg font-bold text-gray-900 dark:text-gray-100">
                Bitbucket
              </h4>
              <p className="text-xs text-nowrap text-gray-500 dark:text-gray-300">
                Add every repository in a workspace for code scanning.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 self-end sm:self-center">
            <Button asChild size="sm">
              <Link href={BITBUCKET_IMPORT_ROUTE}>
                <SettingsIcon size={14} />
                Import repositories
              </Link>
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-gray-600 dark:text-gray-300">
          Connect a Bitbucket Cloud workspace or a Bitbucket Data Center project
          with one read-only token, pick the repositories, and they are added as
          Infrastructure as Code providers.
        </p>
      </CardContent>
    </Card>
  );
};
