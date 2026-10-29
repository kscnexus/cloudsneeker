import { describe, expect, it } from "vitest";

import {
  buildReportParams,
  buildShareLinkEnvelope,
  defaultScheduleFormInput,
  parseRecipients,
  reportGenerateFormSchema,
  reportRunPayloadFromForm,
  reportScheduleFormSchema,
  reportSchedulePayloadFromForm,
  scheduleFormInputFromResource,
} from "@/cloudsneeker/lib/report-form-schema";
import { REPORT_SCHEDULE_PRESET } from "@/cloudsneeker/lib/report-schedule";
import type { ReportScheduleResource } from "@/cloudsneeker/types/reports";

const PROVIDER_ID = "11111111-1111-4111-8111-111111111111";

describe("reportGenerateFormSchema", () => {
  it("accepts a minimal executive report", () => {
    const values = reportGenerateFormSchema.parse({
      reportType: "executive",
      formats: ["pdf"],
    });
    expect(reportRunPayloadFromForm(values)).toEqual({
      reportType: "executive",
      params: { provider_ids: [] },
      formats: ["pdf"],
    });
  });

  it("requires a framework for the compliance report", () => {
    const result = reportGenerateFormSchema.safeParse({
      reportType: "compliance",
      formats: ["pdf"],
    });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.path).toEqual(["complianceId"]);
  });

  it("rejects an end date before the start date", () => {
    const result = reportGenerateFormSchema.safeParse({
      reportType: "cloud_posture",
      dateFrom: "2026-10-20",
      dateTo: "2026-10-01",
      formats: ["pdf"],
    });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.path).toEqual(["dateTo"]);
  });

  it("requires at least one format and only known ones", () => {
    expect(
      reportGenerateFormSchema.safeParse({ reportType: "sca", formats: [] })
        .success,
    ).toBe(false);
    expect(
      reportGenerateFormSchema.safeParse({
        reportType: "sca",
        formats: ["docx"],
      }).success,
    ).toBe(false);
  });

  it("rejects provider ids that are not UUIDs", () => {
    expect(
      reportGenerateFormSchema.safeParse({
        reportType: "sca",
        providerIds: ["prod"],
        formats: ["csv"],
      }).success,
    ).toBe(false);
  });
});

describe("buildReportParams", () => {
  it("sends only the filters that are set", () => {
    expect(
      buildReportParams({
        reportType: "compliance",
        providerIds: [PROVIDER_ID],
        dateFrom: "2026-10-01",
        dateTo: "",
        severityFloor: "high",
        complianceId: "cis_2.0_aws",
      }),
    ).toEqual({
      provider_ids: [PROVIDER_ID],
      date_from: "2026-10-01",
      severity_floor: "high",
      compliance_id: "cis_2.0_aws",
    });
  });

  it("drops the framework for reports that do not accept it", () => {
    expect(
      buildReportParams({
        reportType: "executive",
        providerIds: [],
        dateFrom: "",
        dateTo: "",
        severityFloor: "",
        complianceId: "cis_2.0_aws",
      }),
    ).toEqual({ provider_ids: [] });
  });
});

describe("reportScheduleFormSchema", () => {
  const base = {
    ...defaultScheduleFormInput("executive"),
    name: "Weekly exec",
    recipients: "CISO@example.com, security@example.com\nciso@example.com",
  };

  it("builds a weekly schedule payload", () => {
    const values = reportScheduleFormSchema.parse({
      ...base,
      scheduleHour: "7",
      scheduleWeekday: "5",
      scheduleTimezone: "Asia/Kolkata",
    });
    expect(reportSchedulePayloadFromForm(values)).toEqual({
      name: "Weekly exec",
      reportType: "executive",
      params: { provider_ids: [] },
      formats: ["pdf"],
      scheduleCron: "0 7 * * 5",
      scheduleTimezone: "Asia/Kolkata",
      recipients: ["ciso@example.com", "security@example.com"],
      enabled: true,
    });
  });

  it("builds monthly and custom cron expressions", () => {
    const monthly = reportScheduleFormSchema.parse({
      ...base,
      schedulePreset: REPORT_SCHEDULE_PRESET.MONTHLY,
      scheduleDayOfMonth: 15,
      scheduleHour: 6,
    });
    expect(reportSchedulePayloadFromForm(monthly).scheduleCron).toBe(
      "0 6 15 * *",
    );

    const custom = reportScheduleFormSchema.parse({
      ...base,
      schedulePreset: REPORT_SCHEDULE_PRESET.CUSTOM,
      scheduleCron: " 30 9 * * 1-5 ",
    });
    expect(reportSchedulePayloadFromForm(custom).scheduleCron).toBe(
      "30 9 * * 1-5",
    );
  });

  it("rejects a malformed custom cron", () => {
    const result = reportScheduleFormSchema.safeParse({
      ...base,
      schedulePreset: REPORT_SCHEDULE_PRESET.CUSTOM,
      scheduleCron: "every monday",
    });
    expect(result.success).toBe(false);
    expect(result.error?.issues[0]?.path).toEqual(["scheduleCron"]);
  });

  it("requires valid recipients", () => {
    expect(
      reportScheduleFormSchema.safeParse({ ...base, recipients: "" }).success,
    ).toBe(false);
    const invalid = reportScheduleFormSchema.safeParse({
      ...base,
      recipients: "ciso@example.com, not-an-email",
    });
    expect(invalid.success).toBe(false);
    expect(invalid.error?.issues[0]?.message).toContain("not-an-email");
  });
});

describe("schedule form round trip", () => {
  it("restores a stored schedule into form values", () => {
    const schedule: ReportScheduleResource = {
      type: "cloudsneeker-report-schedules",
      id: "schedule-1",
      attributes: {
        name: "Monthly compliance",
        report_type: "compliance",
        params: {
          provider_ids: [PROVIDER_ID],
          date_from: "2026-10-01T00:00:00+00:00",
          date_to: "2026-10-31T23:59:59.999999+00:00",
          severity_floor: "critical",
          compliance_id: "cis_2.0_aws",
        },
        formats: ["pdf", "csv", "json"],
        schedule_cron: "0 6 1 * *",
        schedule_timezone: "UTC",
        recipients: ["a@example.com", "b@example.com"],
        enabled: false,
      },
    };

    const input = scheduleFormInputFromResource(schedule);
    expect(input).toMatchObject({
      name: "Monthly compliance",
      providerIds: [PROVIDER_ID],
      dateFrom: "2026-10-01",
      dateTo: "2026-10-31",
      severityFloor: "critical",
      complianceId: "cis_2.0_aws",
      formats: ["pdf", "csv"],
      schedulePreset: REPORT_SCHEDULE_PRESET.MONTHLY,
      scheduleHour: 6,
      scheduleDayOfMonth: 1,
      recipients: "a@example.com, b@example.com",
      enabled: false,
    });

    const payload = reportSchedulePayloadFromForm(
      reportScheduleFormSchema.parse(input),
    );
    expect(payload.scheduleCron).toBe("0 6 1 * *");
    expect(payload.params.compliance_id).toBe("cis_2.0_aws");
  });
});

describe("helpers", () => {
  it("parses recipients from mixed separators", () => {
    expect(parseRecipients(" a@x.io;b@x.io\n\nA@x.io ")).toEqual([
      "a@x.io",
      "b@x.io",
    ]);
  });

  it("wraps the share link lifetime", () => {
    expect(buildShareLinkEnvelope(24)).toEqual({
      data: {
        type: "cloudsneeker-report-share-links",
        attributes: { expires_in_hours: 24 },
      },
    });
  });
});
