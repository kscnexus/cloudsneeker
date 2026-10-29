import type { ReportPayload } from "@/cloudsneeker/types/reports";

/** Executive summary payload shaped like `ReportData.to_dict()`. */
export const EXECUTIVE_REPORT_FIXTURE: ReportPayload = {
  report_type: "executive",
  title: "Executive summary",
  generated_at: "2026-10-28T09:00:00+00:00",
  filters: {
    provider_ids: [],
    date_from: "2026-10-01T00:00:00+00:00",
    date_to: "2026-10-28T23:59:59.999999+00:00",
    severity_floor: "high",
    compliance_id: null,
    scan_id: null,
    trend_points: 10,
  },
  headline: "42 open issue(s) across 3 source(s), 5 critical.",
  score: 72.4,
  grade: "C",
  kpis: {
    overall_score: 72.4,
    open_issues: 42,
    critical: 5,
    compliance_pct: 81.25,
  },
  severity_totals: {
    critical: 5,
    high: 37,
    medium: 0,
    low: 0,
    informational: 0,
  },
  status_totals: { pass: 310, fail: 42, muted: 3, manual: 0 },
  trend: [
    { date: "2026-10-20", fail: 50, pass: 300, critical: 7, high: 43 },
    { date: "2026-10-27", fail: 42, pass: 310, critical: 5, high: 37 },
  ],
  top_risks: [
    {
      check_id: "s3_bucket_public_access",
      title: "S3 bucket allows public access",
      severity: "critical",
      findings: 4,
      resources: 4,
      service: "s3",
      impact: "Customer data could be read by anyone on the internet.",
      remediation: "Turn on S3 Block Public Access for the account.",
    },
  ],
  sources: [
    {
      domain: "cloud",
      label: "Cloud posture",
      score: 70,
      grade: "C",
      open_issues: 30,
      critical: 4,
      high: 26,
      coverage: "2 account(s)",
    },
  ],
  compliance: [
    {
      compliance_id: "cis_2.0_aws",
      passed: 13,
      failed: 3,
      manual: 0,
      total: 16,
      pass_pct: 81.25,
    },
  ],
  remediation: [
    {
      priority: 1,
      action: "Fix the 5 critical issue(s) this week.",
      why: "Critical issues are directly exploitable.",
    },
  ],
  tables: [
    {
      key: "domains",
      title: "Score by area",
      columns: [
        { field: "label", header: "Area" },
        { field: "severity", header: "Severity" },
        { field: "open_issues", header: "Open issues" },
      ],
      rows: Array.from({ length: 30 }, (_, index) => ({
        label: `Area ${index + 1}`,
        severity: "high",
        open_issues: index,
      })),
      total: 30,
      truncated: false,
    },
  ],
  empty_state: null,
  extra: {},
};
