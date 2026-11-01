import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { MFA_CODE, MFA_SIGN_IN_MESSAGE } from "@/cloudsneeker/lib/mfa";

import { MfaCodeField } from "./mfa-code-field";

describe("MfaCodeField", () => {
  it("asks for a code and reports typing", () => {
    const onChange = vi.fn();
    render(
      <MfaCodeField
        challenge={MFA_CODE.REQUIRED}
        value=""
        onChange={onChange}
      />,
    );
    const input = screen.getByLabelText("Verification code");
    expect(input).toHaveAttribute("autocomplete", "one-time-code");
    expect(
      screen.getByText(MFA_SIGN_IN_MESSAGE[MFA_CODE.REQUIRED]),
    ).toBeInTheDocument();
    fireEvent.change(input, { target: { value: "123456" } });
    expect(onChange).toHaveBeenCalledWith("123456");
  });

  it("announces a rejected code", () => {
    render(
      <MfaCodeField
        challenge={MFA_CODE.INVALID}
        value="1"
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      MFA_SIGN_IN_MESSAGE[MFA_CODE.INVALID],
    );
  });
});
