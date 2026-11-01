import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SsoPolicyCard } from "./sso-policy-card";

const refresh = vi.fn();
const toast = vi.fn();
const setReject = vi.fn();

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh }) }));
vi.mock("@/components/shadcn/toast/use-toast", () => ({
  useToast: () => ({ toast }),
}));
vi.mock("@/cloudsneeker/actions/sso", () => ({
  setRejectIdpInitiatedSso: (value: boolean) => setReject(value),
}));

const policy = {
  reject_idp_initiated_sso: false,
  signed_requests: true,
  signed_assertions_required: true,
};

describe("SsoPolicyCard", () => {
  beforeEach(() => {
    refresh.mockReset();
    toast.mockReset();
    setReject.mockReset();
  });

  it("shows the signing state", () => {
    render(<SsoPolicyCard policy={{ ...policy, signed_requests: false }} />);
    expect(
      screen.getByText(/no \(no signing key configured\)/),
    ).toBeInTheDocument();
  });

  it("turns rejection of IdP-initiated sign-in on", async () => {
    setReject.mockResolvedValue({ data: {} });
    render(<SsoPolicyCard policy={policy} />);
    fireEvent.click(
      screen.getByRole("button", { name: "Only allow sign-in started here" }),
    );
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(setReject).toHaveBeenCalledWith(true);
  });

  it("reports a refusal", async () => {
    setReject.mockResolvedValue({ error: "No permission", status: 403 });
    render(
      <SsoPolicyCard policy={{ ...policy, reject_idp_initiated_sso: true }} />,
    );
    fireEvent.click(
      screen.getByRole("button", {
        name: "Allow sign-in from the identity provider",
      }),
    );
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ description: "No permission" }),
      ),
    );
    expect(setReject).toHaveBeenCalledWith(false);
    expect(refresh).not.toHaveBeenCalled();
  });
});
