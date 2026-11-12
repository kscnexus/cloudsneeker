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

  it("sends the finding status only for findings reports", () => {
    const base = {
      providerIds: [],
      dateFrom: "",
      dateTo: "",
      severityFloor: "" as const,
      complianceId: "",
      statusScope: "muted" as const,
    };
    expect(buildReportParams({ ...base, reportType: "sca" })).toEqual({
      provider_ids: [],
      status_scope: "muted",
    });
    expect(buildReportParams({ ...base, reportType: "exceptions" })).toEqual({
      provider_ids: [],
    });
    expect(buildReportParams({ ...base, reportType: "executive" })).toEqual({
      provider_ids: [],
    });
  });
});

describe("report sources in the payload", () => {
  const AWS = PROVIDER_ID;
  const AZURE = "33333333-3333-4333-8333-333333333333";
  const REPO = "22222222-2222-4222-8222-222222222222";
  const types = { [AWS]: "aws", [AZURE]: "azure", [REPO]: "iac" };

  it("drops selected sources the report does not read", () => {
    const values = reportGenerateFormSchema.parse({
      reportType: "cloud_posture",
      providerIds: [AWS, REPO],
      formats: ["pdf"],
    });
    expect(reportRunPayloadFromForm(values, types).params.provider_ids).toEqual(
      [AWS],
    );
    expect(
      reportRunPayloadFromForm({ ...values, reportType: "iac" }, types).params
        .provider_ids,
    ).toEqual([REPO]);
    expect(
      reportRunPayloadFromForm({ ...values, reportType: "executive" }, types)
        .params.provider_ids,
    ).toEqual([AWS, REPO]);
  });

  it("keeps compliance to the framework's provider", () => {
    expect(
      buildReportParams(
        {
          reportType: "compliance",
          providerIds: [AWS, AZURE, REPO],
          dateFrom: "",
          dateTo: "",
          severityFloor: "",
          complianceId: "cis_2.0_azure",
        },
        types,
      ).provider_ids,
    ).toEqual([AZURE]);
  });

  it("prunes a schedule switched to another report type", () => {
    const values = reportScheduleFormSchema.parse({
      ...defaultScheduleFormInput("sast"),
      name: "Weekly code",
      providerIds: [AWS, REPO],
      recipients: "dev@example.com",
    });
    expect(
      reportSchedulePayloadFromForm(values, types).params.provider_ids,
    ).toEqual([REPO]);
  });
});

describe("finding status scope", () => {
  it("defaults to active findings", () => {
    const values = reportGenerateFormSchema.parse({
      reportType: "cloud_posture",
      formats: ["pdf"],
    });
    expect(values.statusScope).toBe("active");
    expect(reportRunPayloadFromForm(values).params).toEqual({
      provider_ids: [],
      status_scope: "active",
    });
  });

  it("accepts every scope and rejects unknown ones", () => {
    for (const scope of ["active", "muted", "accepted", "all"]) {
      expect(
        reportGenerateFormSchema.safeParse({
          reportType: "secrets",
          statusScope: scope,
          formats: ["csv"],
        }).success,
      ).toBe(true);
    }
    expect(
      reportGenerateFormSchema.safeParse({
        reportType: "secrets",
        statusScope: "hidden",
        formats: ["csv"],
      }).success,
    ).toBe(false);
  });

  it("reads the stored scope of a schedule and defaults it", () => {
    const schedule = (params: Record<string, unknown>) =>
      ({
        type: "cloudsneeker-report-schedules",
        id: "s1",
        attributes: {
          name: "Weekly",
          report_type: "iac",
          params,
          formats: ["pdf"],
          schedule_cron: "0 8 * * 1",
          schedule_timezone: "UTC",
          recipients: ["a@x.io"],
          enabled: true,
        },
      }) as unknown as ReportScheduleResource;
    expect(
      scheduleFormInputFromResource(schedule({ status_scope: "accepted" }))
        .statusScope,
    ).toBe("accepted");
    expect(scheduleFormInputFromResource(schedule({})).statusScope).toBe(
      "active",
    );
    expect(defaultScheduleFormInput("iac").statusScope).toBe("active");
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
