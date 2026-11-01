import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AdminInvitationCard } from "./admin-invitation-card";
import { CustomerCreateForm } from "./customer-create-form";

const { createCustomerMock, resendAdminInvitationMock, refreshMock } =
  vi.hoisted(() => ({
    createCustomerMock: vi.fn(),
    resendAdminInvitationMock: vi.fn(),
    refreshMock: vi.fn(),
  }));

vi.mock("@/cloudsneeker/actions/operator", () => ({
  createCustomer: createCustomerMock,
  resendAdminInvitation: resendAdminInvitationMock,
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: refreshMock }),
}));

const PLANS = [
  { code: "starter", name: "Starter" },
  { code: "professional", name: "Professional" },
];

const invitation = (token = "ABCDEFGHJKMNPQ") => ({
  id: "i-1",
  email: "admin@acme.example",
  state: "pending",
  expires_at: "2026-11-08T00:00:00+00:00",
  inserted_at: null,
  token,
});

const fill = (label: RegExp, value: string) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value } });

describe("CustomerCreateForm", () => {
  beforeEach(() => {
    createCustomerMock.mockReset();
  });

  it("refuses an invalid email without calling the API", async () => {
    render(<CustomerCreateForm plans={PLANS} defaultPlan="starter" />);
    fill(/Organization name/, "Acme Corp");
    fill(/Administrator email/, "nope");
    fireEvent.submit(screen.getByRole("form", { name: "New customer" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Enter the administrator's email.",
    );
    expect(createCustomerMock).not.toHaveBeenCalled();
  });

  it("creates the customer and shows the invitation link", async () => {
    createCustomerMock.mockResolvedValue({
      data: { type: "cloudsneeker-operator-tenants", id: "tenant-9" },
      meta: { invitation: invitation() },
    });
    render(<CustomerCreateForm plans={PLANS} defaultPlan="starter" />);
    fill(/Organization name/, "Acme Corp");
    fill(/Administrator email/, "Admin@Acme.example");
    fill(/^Plan$/, "professional");
    fireEvent.submit(screen.getByRole("form", { name: "New customer" }));

    expect(await screen.findByText("Acme Corp is ready")).toBeInTheDocument();
    expect(createCustomerMock).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "Acme Corp",
        admin_email: "admin@acme.example",
        plan: "professional",
        status: "active",
      }),
    );
    expect(
      screen.getByText(
        `${window.location.origin}/invitation/accept?invitation_token=ABCDEFGHJKMNPQ`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open customer" })).toHaveAttribute(
      "href",
      "/operator/customers/tenant-9",
    );
  });

  it("shows the API error", async () => {
    createCustomerMock.mockResolvedValue({ error: "Unknown plan." });
    render(<CustomerCreateForm plans={PLANS} defaultPlan="starter" />);
    fill(/Organization name/, "Acme Corp");
    fill(/Administrator email/, "admin@acme.example");
    fireEvent.submit(screen.getByRole("form", { name: "New customer" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Unknown plan.");
  });

  it("asks for the trial end only on a trial", () => {
    render(<CustomerCreateForm plans={PLANS} defaultPlan="starter" />);
    expect(screen.queryByLabelText(/Trial ends/)).not.toBeInTheDocument();
    fill(/^Status$/, "trial");
    expect(screen.getByLabelText(/Trial ends/)).toBeInTheDocument();
  });
});

describe("AdminInvitationCard", () => {
  beforeEach(() => {
    resendAdminInvitationMock.mockReset();
    refreshMock.mockReset();
  });

  it("shows the pending link and sends a new one", async () => {
    resendAdminInvitationMock.mockResolvedValue({
      data: {},
      meta: { invitation: invitation("ZZZZZZZZZZZZZZ") },
    });
    render(
      <AdminInvitationCard
        tenantId="tenant-9"
        invitations={[invitation()]}
        canResend
      />,
    );
    expect(
      screen.getByText(/invitation_token=ABCDEFGHJKMNPQ/),
    ).toBeInTheDocument();

    fireEvent.submit(screen.getByRole("form", { name: "New invitation" }));
    await waitFor(() =>
      expect(
        screen.getByText(/invitation_token=ZZZZZZZZZZZZZZ/),
      ).toBeInTheDocument(),
    );
    expect(resendAdminInvitationMock).toHaveBeenCalledWith("tenant-9", "");
    expect(refreshMock).toHaveBeenCalled();
  });

  it("has no resend form for viewing roles", () => {
    render(
      <AdminInvitationCard
        tenantId="tenant-9"
        invitations={[]}
        canResend={false}
      />,
    );
    expect(screen.getByText(/No pending invitation/)).toBeInTheDocument();
    expect(
      screen.queryByRole("form", { name: "New invitation" }),
    ).not.toBeInTheDocument();
  });
});
