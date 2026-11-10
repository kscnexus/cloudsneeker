# Security Assessment Reporting

Started 2026-11-09. Cloudsneeker has two report families on one run pipeline (`ReportRun`, Celery task `generate_report_task`, artifacts on the shared output volume, share links, schedules, email delivery):

* **Focused reports** (`executive`, `cloud_posture`, `compliance`, `sca`, `sast`, `container`, `iac`, `secrets`, `governance`), in `cloudsneeker_api/reports/data/` and `reports/render/`. Unchanged.
* **Security assessments** (`security_assessment`, `appsec_assessment`, `cloud_assessment`, `governance_assessment`), in `cloudsneeker_api/reports/assessment/`. This page describes them.

The UI wizard is `/reports/assessments` (`ui/app/(cloudsneeker)/reports/assessments/`). The Reports page links to it and keeps the focused reports in its catalog.

## Audit of the Earlier Reporting (2026-11-09)

Data sources: `Scan` and `Finding` (cloud and Application Security scans, latest per provider or per provider and stream), `ResourceFindingMapping`, `ComplianceOverviewSummary` and `ComplianceRequirementOverview`, `CustodianRun` output and summary, `FindingTriage`. The upstream compliance PDFs in `tasks/jobs/reports/` (ThreatScore, ENS, NIS2, CSA, CIS) are per-scan framework reports and were not changed.

Defects found in the earlier Executive Security Summary and shared helpers (`reports/data/common.py`, `reports/data/executive.py`, `reports/render/pdf.py`):

| Area | Defect |
| --- | --- |
| Top risks | `resources` was summed across the severity buckets of one check, so a check with mixed severities double-counted resources. The title, impact, and fix came from any finding of the check, including a PASS one. |
| Units | The compliance "open issues" added failed requirements across frameworks, so one control failing in three frameworks counted three times, and requirements were mixed with findings in one table. |
| Compliance | The average pass rate was an unweighted mean over every framework the scan evaluated, with no difference between frameworks the customer chose and ones that were only available, and no statement that this is not certification. |
| Trend | Each point summed the scans finished that day. A day where one account scanned looked like a large improvement; scope changes read as posture changes. |
| Missing data | Governance and compliance KPIs defaulted to 0 when nothing was assessed; critical and high were hard-coded to 0 for those rows. |
| Duplicates | No deduplication across Application Security streams (repository, filesystem, image, IaC engine) that report the same package or file. |
| Resources | KPIs counted findings only; unique affected resources were not reported. |
| Staleness | The latest scan of a provider could be months old with no warning. |
| PDF | US Letter, portrait only: nine-column tables were squeezed into 7 inches; no bookmarks; no Confidential marking; tables cut at 500 rows. |

## Pipeline

`reports/assessment/`:

| Module | Role |
| --- | --- |
| `collect.py` | Reads records for the scope (database). Non-pass records are loaded (bounded by `REPORT_ASSESSMENT_MAX_FINDINGS`, default 25 000 per area); passed results are counted in SQL. Coverage rows for every assessed and expected source. Coverage-aware trend. Compliance with assessed, enabled, and available frameworks. |
| `accuracy.py` | Status polarity, deduplication, totals, reconciliation, staleness. Pure. |
| `scoring.py` | Area and overall score, grade, KPIs. Pure. |
| `recommend.py` | Recommendation per finding and the P0-P3 priority rules. Pure. |
| `roadmap.py` | Issue groups, stable `F-0001` references, top risks, roadmap windows. Pure. |
| `builder.py` | Report content per type; fills the shared `ReportData` fields for the in-app page. |
| `ai.py` | Optional Seeker AI insights. |
| `quality.py` | Quality control. |
| `render_pdf.py` | The PDF. |
| `export.py` | The CSV. |

`reports/data/__init__.py` sends the four types to `builder.assemble_for`; `render/pdf.py` and `render/tabular.py` hand assessment data to `render_pdf.py` and `export.py`; `runs.py` renders the PDF first (quality control runs there) and stores the quality result, period, scope, warnings, page count, and engine version in `ReportRun.summary`.

## Accuracy Rules

* Polarity: only a `FAIL` status is exposure. `PASS` is a working control. `MANUAL` and unrecognized statuses are not assessed and never counted as either. Check names and message text are never read for polarity. Muted findings are listed apart. Triage does not close a finding the latest scan still reports.
* Deduplication key: provider type, account, resource, check, scanner stream, status. The most recently seen record survives (source id breaks ties); merged ids stay in the CSV. A pass and a fail of the same check never merge; that conflict is counted.
* Reconciliation: status buckets equal records; severity, area, and category buckets equal open findings; unique resources are never more than findings. A broken rule fails quality control.
* Missing data: an area without an assessed source has no score and reads "Not assessed", never 0.
* Staleness: a source older than `stale_days` (default 7) is stale; an expected source with no result is not assessed. Both are listed with a warning.
* Trend: for each sample date the latest result per source up to that date is used. A point is comparable only when it covers the same sources as the end of the period; the stated change uses comparable points only.
* Compliance: assessed (results in scope), enabled (selected, no results), available (offered, not evaluated) are reported apart, with a statement that results are not certification.

## Recommendations and Priority

Each issue (scanner and check) gets: what it is, why it matters, business impact split into confirmed scanner evidence and potential impact, steps, commands only where relevant (package upgrade commands from the recorded fixed version and package URL; CLI or Terraform from the check's own remediation metadata; secret purge with marked `<PLACEHOLDERS>`), validation, prevention, suggested owner, SLA, target date, and expected outcome. `services/finding_fix.py` supplies the fix text and versions.

| Priority | Window | Rule |
| --- | --- | --- |
| P0 | 0-24 hours | Critical, and a credential is exposed or a concrete fix exists |
| P1 | 1-7 days | Other critical; high with an exposed credential or a concrete fix |
| P2 | 8-30 days | Other high; medium |
| P3 | 31-90 days | Low |

Informational findings are not scheduled. No CVSS, EPSS, exploit, or asset-criticality value is computed. A CVSS score is shown only when the scanner recorded it from an advisory, labelled with its source.

## Seeker AI Layer

Opt-in section (`ai_insights`). The model receives a fact sheet of metrics and top issues only and must return JSON insights, each marked fact or interpretation and citing finding references or metric keys from that sheet. Uncited or unknown citations are dropped. No configured LLM, a failed call, or no valid insight gives an explicit "insufficient data" or "unavailable" message. The PDF prints the section separately, labelled as AI-generated.

## PDF

A4 portrait, landscape for the roadmap and appendix. Dark cover, clickable contents, PDF outline (bookmarks), document metadata, Confidential label in the header, "Page X of Y" footer. DejaVu Sans (from matplotlib) embedded for Unicode. Long tables repeat their header row. Headings before long tables reserve room instead of being kept with the whole table. Empty sections print one line instead of a page.

Sections: cover, contents, scope and coverage, executive summary (score ring, KPIs, evidence-based statements with references, area table), risk distribution, trend, top risks, area posture pages, compliance, Seeker AI, remediation roadmap, technical appendix (bounded by `REPORT_ASSESSMENT_APPENDIX_ROWS`, default 1500, most severe first), methodology and data quality, quality control.

## Quality Control

`quality.evaluate` runs after the first render and again on the final render. Checks: narrative present; top risks and roadmap present when there is something to schedule; coverage warnings shown; totals reconcile; exposure lists reference open failed findings only; deduplicated; unassessed areas read "Not assessed"; roadmap items complete; no invented score fields; placeholders marked; AI insights cited; no third-party branding in the text; pages rendered; no blank pages; no heading left at a page bottom; contents and bookmarks; metadata. Any failed check makes the report "Not distributable" (shown in the wizard and history); warnings keep it distributable.

## Tests

* `tests/test_assessment_engine.py`: polarity, dedupe, reconciliation, scoring, recommendations, roadmap, quality, AI parsing, with fixture datasets in `tests/assessment_fixtures.py` (thousands of findings, none, multi-cloud, multi-account, multi-framework, stale, partial, history with a scope change, duplicates, missing evidence).
* `tests/test_assessment_render.py`: every type and dataset renders with no blank pages or orphan headings, bookmarks equal contents entries, metadata, embedded fonts, Unicode, CSV traceability and formula escaping.
* `tests/test_assessment_reports.py`: parameters, collection from real rows, type scoping, period and provider filters, the run pipeline, the API filter and author name.
* UI: `ui/cloudsneeker/lib/assessment-wizard.test.ts`.

The "Cloudsneeker: Tests" workflow renders the sample PDFs to PNG pages and contact sheets (artifact `assessment-report-samples`, kept three days) for visual review.

## Known Gaps

* Trend counts are per scan, before cross-source deduplication, and can differ slightly from the headline totals (stated in the report).
* Governance results come from stored run output, which keeps at most 500 resources per run; trimmed resources are reported as a warning.
* Owners, SLAs, and target dates are suggestions; there is no assignment workflow.
