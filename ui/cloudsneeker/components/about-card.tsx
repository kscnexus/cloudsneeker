import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import { InfoField } from "@/components/shadcn/info-field/info-field";

import type { BrandAttributes } from "../types/brand";

interface BrandLink {
  label: string;
  href: string;
}

interface AboutCardProps {
  attributes: BrandAttributes | undefined;
}

const brandLinks = (attributes: BrandAttributes): BrandLink[] =>
  [
    { label: "Website", href: attributes.website_url },
    { label: "Documentation", href: attributes.docs_url },
    { label: "Support", href: attributes.support_url },
    { label: "Status", href: attributes.status_url },
    { label: "Terms of service", href: attributes.terms_url },
    { label: "Privacy policy", href: attributes.privacy_url },
  ].filter((link) => link.href !== "");

export function AboutCard({ attributes }: AboutCardProps) {
  if (!attributes) {
    return (
      <Card variant="base">
        <CardContent className="text-text-neutral-secondary text-sm">
          Could not load product information. Sign in again or contact your
          administrator.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card variant="base">
      <CardHeader>
        <CardTitle>
          <h2>{attributes.name}</h2>
        </CardTitle>
        <p className="text-text-neutral-secondary text-sm">
          {attributes.tagline}
        </p>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <InfoField label="Vendor" variant="simple">
          {attributes.vendor}
        </InfoField>
        <InfoField label="Links" variant="transparent">
          <ul className="flex flex-wrap gap-x-6 gap-y-2">
            {brandLinks(attributes).map((link) => (
              <li key={link.label}>
                <a
                  href={link.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-text-neutral-primary text-sm underline-offset-4 hover:underline"
                >
                  {link.label}
                </a>
              </li>
            ))}
          </ul>
        </InfoField>
      </CardContent>
    </Card>
  );
}
