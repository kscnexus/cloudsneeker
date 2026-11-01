import { describe, expect, it } from "vitest";

import {
  CUSTOMER_NAME_MAX,
  customerPayload,
  emptyCustomerForm,
  invitationFromMeta,
} from "./operator";

const form = (overrides = {}) => ({
  ...emptyCustomerForm("starter"),
  name: "  Acme Corp ",
  adminEmail: " Admin@Acme.example ",
  ...overrides,
});

describe("customerPayload", () => {
  it("trims, lowercases the email and keeps the plan", () => {
    const { payload, error } = customerPayload(form({ endsAt: "2027-06-30" }));
    expect(error).toBeNull();
    expect(payload).toEqual({
      name: "Acme Corp",
      admin_email: "admin@acme.example",
      plan: "starter",
      status: "active",
      ends_at: "2027-06-30",
      external_customer_id: "",
      notes: "",
    });
  });

  it("sends the trial end only for a trial", () => {
    expect(
      customerPayload(form({ status: "trial", trialEndsAt: "2027-01-31" }))
        .payload?.trial_ends_at,
    ).toBe("2027-01-31");
    expect(
      customerPayload(form({ trialEndsAt: "2027-01-31" })).payload,
    ).not.toHaveProperty("trial_ends_at");
  });

  it("leaves the plan out when none is picked (API default plan)", () => {
    expect(customerPayload(form({ plan: "" })).payload).not.toHaveProperty(
      "plan",
    );
  });

  it.each([
    [{ name: " " }, "Organization name is required."],
    [
      { name: "x".repeat(CUSTOMER_NAME_MAX + 1) },
      `Organization name: up to ${CUSTOMER_NAME_MAX} characters.`,
    ],
    [{ adminEmail: "" }, "Enter the administrator's email."],
    [{ adminEmail: "not an email" }, "Enter the administrator's email."],
  ])("refuses %o", (overrides, message) => {
    expect(customerPayload(form(overrides))).toEqual({
      payload: null,
      error: message,
    });
  });
});

describe("invitationFromMeta", () => {
  it("reads meta.invitation", () => {
    const invitation = {
      id: "i-1",
      email: "admin@acme.example",
      state: "pending",
      expires_at: "2026-11-08T00:00:00+00:00",
      inserted_at: null,
      token: "ABCDEFGHJKMNPQ",
    };
    expect(invitationFromMeta({ data: {}, meta: { invitation } })).toEqual(
      invitation,
    );
  });

  it("is null for an error or a missing token", () => {
    expect(invitationFromMeta({ error: "nope" })).toBeNull();
    expect(
      invitationFromMeta({ meta: { invitation: { id: "i" } } }),
    ).toBeNull();
  });
});
