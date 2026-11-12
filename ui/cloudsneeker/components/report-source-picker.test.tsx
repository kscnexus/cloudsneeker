import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it } from "vitest";

import { ReportSourcePicker } from "./report-source-picker";

const sources = [
  { id: "aws", label: "Prod", providerType: "aws" },
  { id: "m365", label: "Tenant", providerType: "m365" },
  { id: "repo", label: "github.com/acme/api", providerType: "iac" },
  { id: "img", label: "acme/web:1.2", providerType: "image" },
];

const many = Array.from({ length: 12 }, (_, index) => ({
  id: `repo-${index}`,
  label: `github.com/acme/service-${index}`,
  providerType: "iac",
}));

const Harness = ({
  reportType,
  initial = [],
  list = sources,
}: {
  reportType: string;
  initial?: string[];
  list?: typeof sources;
}) => {
  const [selected, setSelected] = useState<string[]>(initial);
  return (
    <ReportSourcePicker
      reportType={reportType}
      sources={list}
      selected={selected}
      onToggle={(id) =>
        setSelected((current) =>
          current.includes(id)
            ? current.filter((item) => item !== id)
            : [...current, id],
        )
      }
      onClear={() => setSelected([])}
      idPrefix="test"
    />
  );
};

describe("ReportSourcePicker", () => {
  it("lists only cloud and SaaS accounts for a cloud report", () => {
    render(<Harness reportType="cloud_posture" />);
    expect(
      screen.getByText("Showing cloud and SaaS accounts only."),
    ).toBeInTheDocument();
    const cloud = screen.getByRole("group", { name: "Cloud accounts" });
    expect(within(cloud).getByLabelText(/Prod/)).toBeInTheDocument();
    expect(
      screen.getByRole("group", { name: "SaaS accounts" }),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText(/acme\/api/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/acme\/web/)).not.toBeInTheDocument();
    expect(
      screen.getByText("All 2 relevant source(s) you can see are included."),
    ).toBeInTheDocument();
  });

  it("lists repositories and images for an application report", () => {
    render(<Harness reportType="sca" />);
    expect(
      screen.getByRole("group", { name: "Repositories and code" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("group", { name: "Container images" }),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText(/Prod/)).not.toBeInTheDocument();
  });

  it("lists every source for an executive report", () => {
    render(<Harness reportType="executive" />);
    expect(screen.getAllByRole("checkbox")).toHaveLength(4);
  });

  it("counts and clears the selection, and flags sources left out", async () => {
    render(<Harness reportType="cloud_posture" initial={["aws", "repo"]} />);
    expect(screen.getByText("1 of 2 selected.")).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(
      "1 selected source(s) do not apply",
    );
    await userEvent.click(screen.getByRole("button", { name: /clear/i }));
    expect(
      screen.getByText("All 2 relevant source(s) you can see are included."),
    ).toBeInTheDocument();
  });

  it("searches a long list", async () => {
    render(<Harness reportType="iac" list={many} />);
    expect(screen.getAllByRole("checkbox")).toHaveLength(12);
    await userEvent.type(screen.getByLabelText("Search sources"), "service-1");
    // service-1, service-10, service-11
    expect(screen.getAllByRole("checkbox")).toHaveLength(3);
    await userEvent.clear(screen.getByLabelText("Search sources"));
    await userEvent.type(screen.getByLabelText("Search sources"), "nothing");
    expect(
      screen.getByText("No source matches the search."),
    ).toBeInTheDocument();
  });

  it("hides the search on a short list and explains an empty one", () => {
    render(<Harness reportType="governance" list={[sources[2]]} />);
    expect(screen.queryByLabelText("Search sources")).not.toBeInTheDocument();
    expect(
      screen.getByText(/No relevant source is connected/),
    ).toBeInTheDocument();
  });
});
