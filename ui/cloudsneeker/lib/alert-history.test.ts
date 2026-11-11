import { describe, expect, it } from "vitest";

import {
  ALERT_EVENT_STATUS,
  alertEventTransitions,
  alertHistoryQuery,
  alertLinkLabel,
  severitySummary,
  toAlertEvents,
} from "./alert-history";
import { parseListFilters } from "./list-filters";

describe("alertHistoryQuery", () => {
  it("maps status, module, search and page to API filters", () => {
    // Given
    const filters = parseListFilters({
      q: "prod",
      status: "acknowledged",
      type: "application_security",
      page: "3",
    });
    // When
    const query = alertHistoryQuery(filters);
    // Then
    expect(query).toEqual({
      "page[size]": "25",
      "page[number]": "3",
      sort: "-inserted_at",
      "filter[search]": "prod",
      "filter[status]": "acknowledged",
      "filter[area]": "application_security",
    });
  });

  it("drops unknown status and module values", () => {
    const query = alertHistoryQuery(
      parseListFilters({ status: "closed", type: "billing" }),
    );
    expect(query).not.toHaveProperty("filter[status]");
    expect(query).not.toHaveProperty("filter[area]");
  });
});

describe("alertEventTransitions", () => {
  it("offers acknowledge, resolve and dismiss on an open event", () => {
    expect(
      alertEventTransitions(ALERT_EVENT_STATUS.OPEN).map((item) => item.label),
    ).toEqual(["Acknowledge", "Resolve", "Dismiss"]);
  });

  it("offers reopen on a closed event", () => {
    expect(alertEventTransitions(ALERT_EVENT_STATUS.RESOLVED)).toEqual([
      { status: "open", label: "Reopen" },
    ]);
  });
});

describe("toAlertEvents", () => {
  it("flattens JSON:API rows in module order", () => {
    // Given
    const response = {
      data: [
        {
          id: "e-1",
          type: "alert-events",
          attributes: {
            rule_id: "r-1",
            rule_name: "Critical code",
            trigger: "after_scan",
            inserted_at: "2026-11-12T08:00:00Z",
            total: 5,
            area_counts: { application_security: 3, cloud: 2, governance: 0 },
            severity_counts: { high: 4, critical: 1 },
            links: ["/findings?a", 7],
            delivered: true,
            status: "acknowledged",
            status_changed_at: "2026-11-12T09:00:00Z",
            status_changed_by: { id: "u-1", name: "Ana" },
            note: "on it",
          },
        },
        { type: "alert-events", attributes: {} },
      ],
    };
    // When
    const [event, ...rest] = toAlertEvents(response);
    // Then
    expect(rest).toEqual([]);
    expect(event.areas.map((item) => [item.area, item.count])).toEqual([
      ["cloud", 2],
      ["application_security", 3],
    ]);
    expect(event.links).toEqual(["/findings?a"]);
    expect(event.statusChange).toEqual({
      at: "2026-11-12T09:00:00Z",
      by: "Ana",
    });
    expect(event.status).toBe("acknowledged");
  });

  it("returns nothing for an error result", () => {
    expect(toAlertEvents({ error: "boom" })).toEqual([]);
  });
});

describe("severitySummary", () => {
  it("lists severities most severe first and skips zeros", () => {
    expect(severitySummary({ low: 2, critical: 1, high: 0 })).toBe(
      "critical 1 · low 2",
    );
  });
});

describe("alertLinkLabel", () => {
  it("names the page a link opens", () => {
    expect(alertLinkLabel("https://x/application-security/t/runs/r")).toBe(
      "Application Security run",
    );
    expect(alertLinkLabel("https://x/governance/p/runs/r")).toBe(
      "Governance run",
    );
    expect(alertLinkLabel("https://x/findings?filter")).toBe("Findings");
  });
});
