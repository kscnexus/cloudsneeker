"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { FOCUS_RING_CLASS } from "@/cloudsneeker/lib/ui-classes";
import { OPERATOR_ROUTE } from "@/cloudsneeker/routes";
import { cn } from "@/lib/utils";

export const OPERATOR_NAV_LINKS = [
  { href: OPERATOR_ROUTE.OVERVIEW, label: "Overview" },
  { href: OPERATOR_ROUTE.CUSTOMERS, label: "Customers" },
  { href: OPERATOR_ROUTE.PLANS, label: "Plans" },
  { href: OPERATOR_ROUTE.AUDIT, label: "Audit" },
] as const;

export const isOperatorLinkActive = (
  pathname: string,
  href: string,
): boolean =>
  href === OPERATOR_ROUTE.OVERVIEW
    ? pathname === href
    : pathname === href || pathname.startsWith(`${href}/`);

export const OperatorNav = () => {
  const pathname = usePathname() ?? "";
  return (
    <nav aria-label="Operator console" className="flex flex-wrap gap-1">
      {OPERATOR_NAV_LINKS.map((link) => {
        const active = isOperatorLinkActive(pathname, link.href);
        return (
          <Link
            key={link.href}
            href={link.href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "rounded-md px-3 py-1.5 text-sm transition-colors",
              active
                ? "bg-bg-neutral-tertiary text-text-neutral-primary font-medium"
                : "text-text-neutral-secondary hover:text-text-neutral-primary",
              FOCUS_RING_CLASS,
            )}
          >
            {link.label}
          </Link>
        );
      })}
    </nav>
  );
};
