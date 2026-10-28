import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { BRAND } from "@/cloudsneeker/brand";

import { AuthLayout } from "./auth-layout";

describe("AuthLayout", () => {
  it("renders the product story beside the form", () => {
    render(
      <AuthLayout title="Sign in">
        <p>form content</p>
      </AuthLayout>,
    );

    // The brand renders twice: in the product story and, for small screens,
    // above the form. Assert the one inside the story panel.
    const story = screen.getByRole("region", { name: "Product overview" });
    const brand = within(story).getByRole("img", { name: BRAND.name });
    expect(screen.getAllByRole("img", { name: BRAND.name })).toHaveLength(2);
    const title = screen.getByText("Sign in");

    expect(brand).toBeVisible();
    expect(title).toBeVisible();
    expect(
      screen.getByText("See risk clearly. Act before exposure becomes impact."),
    ).toBeVisible();
    expect(screen.getByText("Continuous posture")).toBeVisible();
  });

  it("renders the footer outside the form card, below it", () => {
    render(
      <AuthLayout title="Sign in" footer={<p>footer link</p>}>
        <p>form content</p>
      </AuthLayout>,
    );

    const content = screen.getByText("form content");
    const footer = screen.getByText("footer link");
    const card = content.parentElement!;

    expect(card.contains(footer)).toBe(false);
    expect(
      content.compareDocumentPosition(footer) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
  });
});
