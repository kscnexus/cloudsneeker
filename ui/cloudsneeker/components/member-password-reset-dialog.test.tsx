import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { temporaryPasswordFromMeta } from "@/cloudsneeker/lib/operator";
import { OPERATOR_CAPABILITY } from "@/cloudsneeker/types/operator";

import { MemberPasswordResetDialog } from "./member-password-reset-dialog";

const { resetUserPasswordMock } = vi.hoisted(() => ({
  resetUserPasswordMock: vi.fn(),
}));

vi.mock("@/cloudsneeker/actions/operator", () => ({
  resetUserPassword: resetUserPasswordMock,
}));

const TEMPORARY = "Tmp-Pass_word42!xyzQ";

const renderDialog = () =>
  render(
    <MemberPasswordResetDialog
      tenantId="tenant-1"
      userId="user-1"
      email="member@acme.example"
    />,
  );

const openDialog = () =>
  fireEvent.click(
    screen.getByRole("button", {
      name: "Reset password for member@acme.example",
    }),
  );

const confirm = () =>
  fireEvent.click(screen.getByRole("button", { name: "Reset password" }));

describe("MemberPasswordResetDialog", () => {
  beforeEach(() => {
    resetUserPasswordMock.mockReset();
  });

  it("asks for confirmation before resetting", () => {
    renderDialog();
    openDialog();
    expect(
      screen.getByText("Give member@acme.example a new temporary password?"),
    ).toBeInTheDocument();
    expect(resetUserPasswordMock).not.toHaveBeenCalled();
  });

  it("cancel closes without calling the API", async () => {
    renderDialog();
    openDialog();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(resetUserPasswordMock).not.toHaveBeenCalled();
  });

  it("shows the temporary password once after confirming", async () => {
    resetUserPasswordMock.mockResolvedValue({
      data: {
        type: "cloudsneeker-password-resets",
        id: "user-1",
        attributes: { email: "member@acme.example" },
      },
      meta: { temporary_password: TEMPORARY },
    });
    renderDialog();
    openDialog();
    confirm();

    expect(await screen.findByText(TEMPORARY)).toBeInTheDocument();
    expect(resetUserPasswordMock).toHaveBeenCalledWith("tenant-1", "user-1");

    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    // Opening again starts over: the password is gone.
    openDialog();
    expect(screen.queryByText(TEMPORARY)).not.toBeInTheDocument();
  });

  it("shows the API error and no password", async () => {
    resetUserPasswordMock.mockResolvedValue({
      error: "This account belongs to a platform operator.",
    });
    renderDialog();
    openDialog();
    confirm();

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "This account belongs to a platform operator.",
    );
    expect(screen.queryByText(TEMPORARY)).not.toBeInTheDocument();
  });
});

describe("temporaryPasswordFromMeta", () => {
  it("reads the password from meta", () => {
    expect(
      temporaryPasswordFromMeta({ meta: { temporary_password: "abc" } }),
    ).toBe("abc");
  });

  it("is null for errors and missing values", () => {
    expect(temporaryPasswordFromMeta({ error: "nope" })).toBeNull();
    expect(temporaryPasswordFromMeta({ meta: {} })).toBeNull();
    expect(temporaryPasswordFromMeta(null)).toBeNull();
  });
});

describe("OPERATOR_CAPABILITY", () => {
  it("names the password reset capability the API sends", () => {
    expect(OPERATOR_CAPABILITY.RESET_PASSWORDS).toBe("reset_passwords");
  });
});
