import { render } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { MfaEnrolmentRedirect } from "./mfa-enrolment-redirect";

const replace = vi.fn();
let pathname = "/";

vi.mock("next/navigation", () => ({
  usePathname: () => pathname,
  useRouter: () => ({ replace }),
}));

describe("MfaEnrolmentRedirect", () => {
  beforeEach(() => {
    replace.mockReset();
    pathname = "/";
  });

  it("sends members who must enrol to the Security page", () => {
    render(<MfaEnrolmentRedirect required />);
    expect(replace).toHaveBeenCalledWith("/settings/security");
  });

  it("stays on the Security page", () => {
    pathname = "/settings/security";
    render(<MfaEnrolmentRedirect required />);
    expect(replace).not.toHaveBeenCalled();
  });

  it("does nothing when MFA is not required", () => {
    render(<MfaEnrolmentRedirect required={false} />);
    expect(replace).not.toHaveBeenCalled();
  });
});
