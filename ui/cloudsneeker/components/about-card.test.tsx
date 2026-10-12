import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { BrandAttributes } from "../types/brand";

import { AboutCard } from "./about-card";

const attributes: BrandAttributes = {
  name: "Cloudsneeker",
  short_name: "Cloudsneeker",
  vendor: "Cloudsneeker Ltd",
  tagline: "Cloud security posture, continuously.",
  website_url: "https://cloudsneeker.example",
  docs_url: "https://docs.cloudsneeker.example",
  support_url: "https://support.cloudsneeker.example",
  status_url: "",
  terms_url: "https://cloudsneeker.example/terms",
  privacy_url: "https://cloudsneeker.example/privacy",
  logo_url: "",
};

describe("AboutCard", () => {
  it("renders the brand identity and the help links", () => {
    // When
    render(<AboutCard attributes={attributes} />);

    // Then
    expect(
      screen.getByRole("heading", { name: "Cloudsneeker" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Cloud security posture, continuously."),
    ).toBeInTheDocument();
    expect(screen.getByText("Cloudsneeker Ltd")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Documentation" })).toHaveAttribute(
      "href",
      "https://docs.cloudsneeker.example",
    );
    expect(screen.getByRole("link", { name: "Support" })).toHaveAttribute(
      "href",
      "https://support.cloudsneeker.example",
    );
    expect(
      screen.getByRole("link", { name: "Terms of service" }),
    ).toHaveAttribute("href", "https://cloudsneeker.example/terms");
  });

  it("skips links whose URL is empty", () => {
    // When
    render(<AboutCard attributes={attributes} />);

    // Then
    expect(screen.queryByRole("link", { name: "Status" })).toBeNull();
  });

  it("opens external links in a new tab safely", () => {
    // When
    render(<AboutCard attributes={attributes} />);

    // Then
    const link = screen.getByRole("link", { name: "Website" });
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("explains when the brand could not be loaded", () => {
    // When
    render(<AboutCard attributes={undefined} />);

    // Then
    expect(
      screen.getByText(/could not load product information/i),
    ).toBeInTheDocument();
  });
});
