import { describe, expect, it } from "vitest";

import { isSocialProviderReady, socialProviderName } from "./social-providers";

describe("social providers", () => {
  it("is ready only when enabled with a URL", () => {
    expect(
      isSocialProviderReady({ isOAuthEnabled: true, url: "https://x" }),
    ).toBe(true);
    expect(isSocialProviderReady({ isOAuthEnabled: true })).toBe(false);
    expect(isSocialProviderReady({ url: "https://x" })).toBe(false);
  });

  it("shows the provider name", () => {
    expect(socialProviderName("Continue with Google")).toBe("Google");
    expect(socialProviderName("Continue with Github")).toBe("GitHub");
  });
});
