import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { PageNav } from "./page-nav";

describe("PageNav", () => {
  it("links numbered pages, first, previous, next and last", () => {
    render(
      <PageNav
        page={5}
        pages={16}
        count={385}
        noun="findings"
        hrefFor={(page) => `/list?page=${page}`}
      />,
    );

    expect(screen.getByText("385 findings")).toBeInTheDocument();
    expect(screen.getByText("Page 5 of 16")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Page 4" })).toHaveAttribute(
      "href",
      "/list?page=4",
    );
    expect(screen.getByRole("link", { name: "Page 16" })).toHaveAttribute(
      "href",
      "/list?page=16",
    );
    expect(screen.getByLabelText("Page 5")).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(
      screen.getByRole("link", { name: "Go to first page" }),
    ).toHaveAttribute("href", "/list?page=1");
    expect(
      screen.getByRole("link", { name: "Go to next page" }),
    ).toHaveAttribute("href", "/list?page=6");
    expect(screen.queryByRole("link", { name: "Page 10" })).toBeNull();
  });

  it("disables first and previous on the first page", () => {
    render(<PageNav page={1} pages={3} hrefFor={(page) => `?p=${page}`} />);
    expect(screen.getByLabelText("Go to previous page")).toHaveAttribute(
      "aria-disabled",
      "true",
    );
    expect(
      screen.queryByRole("link", { name: "Go to previous page" }),
    ).toBeNull();
  });

  it("calls onSelect in client tables", async () => {
    const onSelect = vi.fn();
    render(<PageNav page={2} pages={3} onSelect={onSelect} />);
    await userEvent.click(screen.getByRole("button", { name: "Page 3" }));
    expect(onSelect).toHaveBeenCalledWith(3);
  });

  it("shows only the count for a single page", () => {
    render(<PageNav page={1} pages={1} count={4} noun="alerts" />);
    expect(screen.getByText("4 alerts")).toBeInTheDocument();
    expect(screen.queryByLabelText("Go to next page")).toBeNull();
  });
});
