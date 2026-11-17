import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  LIMIT_WARNING_RATIO,
  limitUsageNote,
  limitUsageRows,
} from "@/cloudsneeker/lib/entitlements";

import { UsageBars } from "./usage-bars";

const row = (limit: string) => {
  const item = document.querySelector(`[data-limit="${limit}"]`);
  if (!item) throw new Error(`No usage row for ${limit}`);
  return item;
};

describe("UsageBars warning at 80% of a limit", () => {
  it("warns from 80% of the limit and not below it", () => {
    render(
      <UsageBars
        usage={{
          scans_this_month: 80,
          seeker_ai_requests_this_month: 79,
        }}
        limits={{ scans_per_month: 100, seeker_ai_requests_per_month: 100 }}
      />,
    );

    const scans = row("scans_per_month");
    expect(scans).toHaveAttribute("data-usage-level", "warning");
    expect(scans).toHaveTextContent("80% of the plan limit used");
    expect(scans.querySelector("[data-usage-note]")).toHaveClass(
      "text-text-warning-primary",
    );
    expect(
      screen.getByRole("progressbar", { name: "Scans per month" })
        .firstElementChild,
    ).toHaveClass("bg-bg-warning");

    const assistant = row("seeker_ai_requests_per_month");
    expect(assistant).toHaveAttribute("data-usage-level", "ok");
    expect(assistant.querySelector("[data-usage-note]")).toBeNull();
    expect(
      screen.getByRole("progressbar", { name: "Assistant requests per month" })
        .firstElementChild,
    ).toHaveClass("bg-button-tertiary");
  });

  it("says the limit is reached at 100% and flags overuse above it", () => {
    render(
      <UsageBars
        usage={{ scans_this_month: 100, seeker_ai_requests_this_month: 501 }}
        limits={{ scans_per_month: 100, seeker_ai_requests_per_month: 500 }}
      />,
    );

    const scans = row("scans_per_month");
    expect(scans).toHaveAttribute("data-usage-level", "warning");
    expect(scans).toHaveTextContent("Plan limit reached");

    const assistant = row("seeker_ai_requests_per_month");
    expect(assistant).toHaveAttribute("data-usage-level", "over");
    expect(assistant).toHaveTextContent("Over the plan limit");
    expect(assistant.querySelector("[data-usage-note]")).toHaveClass(
      "text-text-error-primary",
    );
  });

  it("never warns for an unlimited or untracked limit", () => {
    render(
      <UsageBars
        usage={{ scans_this_month: 9000, providers: 4 }}
        limits={{ scans_per_month: null, users: 5 }}
      />,
    );

    expect(document.querySelector("[data-usage-note]")).toBeNull();
    expect(row("scans_per_month")).toHaveAttribute("data-usage-level", "ok");
    expect(row("users")).toHaveAttribute("data-usage-level", "ok");
  });
});

describe("limitUsageNote", () => {
  const rowFor = (used: number, limit: number | null) => {
    const found = limitUsageRows(
      { scans_this_month: used },
      { scans_per_month: limit },
    ).find((item) => item.key === "scans_per_month");
    if (!found) throw new Error("No scans row");
    return found;
  };

  it("uses 0.8 as the warning share", () => {
    expect(LIMIT_WARNING_RATIO).toBe(0.8);
  });

  it.each([
    [0, 120, false, null],
    [95, 120, false, null],
    [96, 120, true, "80% of the plan limit used"],
    [119, 120, true, "99% of the plan limit used"],
    [120, 120, true, "Plan limit reached"],
    [121, 120, false, "Over the plan limit"],
    [0, 0, false, null],
    [500, null, false, null],
  ])("%i of %s -> warning %s, note %s", (used, limit, warning, note) => {
    const usage = rowFor(used, limit);
    expect(usage.warning).toBe(warning);
    expect(limitUsageNote(usage)).toBe(note);
  });
});
