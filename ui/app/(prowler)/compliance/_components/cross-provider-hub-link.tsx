import { SquareArrowOutUpRight } from "lucide-react";
import Link from "next/link";

import { docsUrl } from "@/cloudsneeker/brand"; // cloudsneeker-hook
import { Button } from "@/components/shadcn/button/button";

interface CrossProviderHubLinkProps {
  complianceId: string;
}

export const CrossProviderHubLink = ({
  complianceId,
}: CrossProviderHubLinkProps) => (
  <Button variant="link" size="link-xs" asChild>
    <Link
      href={docsUrl(`compliance/${encodeURIComponent(complianceId)}`)} // cloudsneeker-hook
      target="_blank"
      rel="noopener noreferrer"
      prefetch={false}
    >
      View documentation
      <SquareArrowOutUpRight />
    </Link>
  </Button>
);
