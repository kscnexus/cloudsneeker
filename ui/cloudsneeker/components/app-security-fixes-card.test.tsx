import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { AreaFindingAttributes } from "@/cloudsneeker/types/area-findings";

import { AppSecurityFixesCard } from "./app-security-fixes-card";

const fix = (
  uid: string,
  overrides: Partial<AreaFindingAttributes> = {},
): AreaFindingAttributes =>
  ({
    uid,
    title: `Title ${uid}`,
    check_id: "CVE-2026-1",
    location: "PyJWT 2.8.0",
    source_name: "web-repo",
    severity: "critical",
    fix_available: true,
    fix_summary: "Upgrade PyJWT from 2.8.0 to 2.10.1 or later.",
    installed_version: "2.8.0",
    fixed_version: "2.10.1",
    fix_references: [],
    remediation: "",
    ...overrides,
  }) as AreaFindingAttributes;

describe("AppSecurityFixesCard", () => {
  it("counts fixable findings and links each count to the filtered list", () => {
    render(<AppSecurityFixesCard fixable={30} unfixable={10} topFixes={[]} />);

    const status = screen.getByRole("list", { name: "Fix status" });
    const links = within(status).getAllByRole("link");
    expect(links[0]).toHaveAttribute(
      "href",
      "/application-security/findings?fix=available",
    );
    expect(links[0]).toHaveTextContent("30");
    expect(links[0]).toHaveTextContent("75% of open findings");
    expect(links[1]).toHaveAttribute(
      "href",
      "/application-security/findings?fix=unavailable",
    );
    expect(screen.queryByRole("list", { name: "Top fixes" })).toBeNull();
  });

  it("lists the top fixes with their upgrade", () => {
    render(
      <AppSecurityFixesCard fixable={1} unfixable={0} topFixes={[fix("a")]} />,
    );

    const list = screen.getByRole("list", { name: "Top fixes" });
    expect(within(list).getByText("Upgrade to 2.10.1")).toBeInTheDocument();
    expect(
      within(list).getByText("Upgrade PyJWT from 2.8.0 to 2.10.1 or later."),
    ).toBeInTheDocument();
    expect(within(list).getByRole("link", { name: "Title a" })).toHaveAttribute(
      "href",
      "/application-security/findings?q=a",
    );
  });

  it("shows a dash when a count could not be loaded", () => {
    render(
      <AppSecurityFixesCard fixable={null} unfixable={null} topFixes={[]} />,
    );

    expect(screen.getAllByText("—")).toHaveLength(2);
  });
});
