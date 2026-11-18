import { describe, expect, it } from "vitest";

import { authAutoComplete } from "./auth-fields";

describe("authAutoComplete", () => {
  it("names the email and password fields for password managers", () => {
    expect(authAutoComplete({ type: "email" })).toBe("email");
    expect(authAutoComplete({ password: true })).toBe("current-password");
    expect(authAutoComplete({ confirmPassword: true })).toBe("new-password");
  });

  it("leaves other inputs alone", () => {
    expect(authAutoComplete({ type: "text" })).toBeUndefined();
    expect(authAutoComplete({})).toBeUndefined();
  });
});
