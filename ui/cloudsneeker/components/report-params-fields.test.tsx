import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useForm } from "react-hook-form";
import { describe, expect, it } from "vitest";

import {
  asReportParamsForm,
  ReportParamsFields,
  type ReportParamsFieldValues,
} from "./report-params-fields";

let latest: ReportParamsFieldValues | null = null;

const Harness = ({ reportType }: { reportType: string }) => {
  const form = useForm<ReportParamsFieldValues>({
    defaultValues: {
      reportType,
      providerIds: [],
      dateFrom: "",
      dateTo: "",
      severityFloor: "",
      complianceId: "",
      statusScope: "active",
      formats: ["pdf"],
    },
  });
  latest = form.watch();
  return (
    <ReportParamsFields
      form={asReportParamsForm(form)}
      idPrefix="test"
      providers={[]}
      frameworks={[]}
    />
  );
};

describe("ReportParamsFields finding status", () => {
  it("offers the finding status on findings reports", async () => {
    render(<Harness reportType="cloud_posture" />);
    const select = screen.getByLabelText("Finding status");
    expect(
      screen
        .getAllByRole("option", { name: /findings$/ })
        .map((o) => o.textContent),
    ).toEqual([
      "Active findings",
      "Muted findings",
      "Risk-accepted findings",
      "All failed findings",
    ]);
    await userEvent.selectOptions(select, "muted");
    expect(latest?.statusScope).toBe("muted");
  });

  it("hides it on reports that do not take it", () => {
    render(<Harness reportType="exceptions" />);
    expect(screen.queryByLabelText("Finding status")).not.toBeInTheDocument();
  });
});
