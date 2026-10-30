import type { ReactNode } from "react";

import { getOperatorMe } from "@/cloudsneeker/actions/operator";
import {
  OperatorNotAvailable,
  OperatorShell,
} from "@/cloudsneeker/components/operator-shell";
import { responseResource } from "@/cloudsneeker/lib/operator";
import type { OperatorMeAttributes } from "@/cloudsneeker/types/operator";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Operator console",
  robots: { index: false, follow: false },
};

/**
 * Only active platform operators get past this layout. The API answers 404
 * to everyone else (tenant administrators included), so they see
 * "Not available" and nothing about the console.
 */
export default async function OperatorLayout({
  children,
}: {
  children: ReactNode;
}) {
  const me = responseResource<{ attributes: OperatorMeAttributes }>(
    await getOperatorMe(),
  );
  if (!me) return <OperatorNotAvailable />;
  return <OperatorShell me={me.attributes}>{children}</OperatorShell>;
}
