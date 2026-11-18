import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SocialButtons } from "./social-buttons";

describe("SocialButtons", () => {
  // cloudsneeker-hook: buttons show the provider name, and providers that are
  // not set up are left out.
  it("renders provider links with their names", () => {
    render(
      <SocialButtons
        googleAuthUrl="https://accounts.google.com/auth"
        githubAuthUrl="https://github.com/login/oauth"
        isGoogleOAuthEnabled
        isGithubOAuthEnabled
      />,
    );

    const google = screen.getByRole("link", { name: "Continue with Google" });
    const github = screen.getByRole("link", { name: "Continue with Github" });

    expect(google.textContent).toBe("Google");
    expect(github.textContent).toBe("GitHub");
  });

  it("renders bundled provider logos without fetching icon data", () => {
    render(
      <SocialButtons
        googleAuthUrl="https://accounts.google.com/auth"
        githubAuthUrl="https://github.com/login/oauth"
        isGoogleOAuthEnabled
        isGithubOAuthEnabled
      />,
    );

    const google = screen.getByRole("link", { name: "Continue with Google" });
    const github = screen.getByRole("link", { name: "Continue with Github" });

    expect(google.querySelector("svg path")).toBeInTheDocument();
    expect(github.querySelector("svg path")).toBeInTheDocument();
  });

  it("leaves out providers that are not set up", () => {
    render(<SocialButtons />);

    expect(
      screen.queryByRole("button", { name: "Continue with Google" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Continue with Github" }),
    ).not.toBeInTheDocument();
  });
});
