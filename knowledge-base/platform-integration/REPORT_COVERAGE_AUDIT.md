# Report Coverage Audit

Catalogue read from `api/src/backend/cloudsneeker_api/reports/catalog.py` on 2026-11-11 and updated on 2026-11-12 (RC-002, RC-003, PI-022). Every report type renders PDF, Excel, CSV and JSON. Common parameters: providers, date range, severity floor, trend points; compliance also takes a framework and scan; the findings reports also take `status_scope`. All data comes from database queries (`reports/data/*.py`); nothing is static.

## Catalogue

| Report | Module | Data | Muted findings | Triage |
| --- | --- | --- | --- | --- |
| Executive | Cross-module | Cloud, application, compliance, governance scores | Counted separately (`muted_findings`) | In progress, resolved, false positive, risk accepted counts |
| Cloud posture | Cloud Security | Findings, services, trend | Counted; listed with `status_scope=muted` or `all` | `status_scope=active` leaves out risk-accepted findings; `accepted` lists them |
| Compliance | Cloud Security | Framework requirements for a scan | — | — |
| SCA | Application Security | Dependency findings, exploitation column | As cloud posture | As cloud posture |
| SAST | Application Security | Code findings | As cloud posture | As cloud posture |
| Container | Application Security | Image findings | As cloud posture | As cloud posture |
| IaC | Application Security | Misconfigurations | As cloud posture | As cloud posture |
| Secrets | Application Security | Secret findings | As cloud posture | As cloud posture |
| Governance | Cloud Governance | Dry-run matches per policy, new and resolved deltas | `muted_resources` KPI (RC-001); executive open issues exclude them | — |
| Exceptions | Cross-module | Mute rules (name, reason, enabled, creator, findings, date) and accepted risks (reason, approver, approval and expiry dates, state); expired and expiring-in-30-days counts; expired acceptance history; per-area summary | Every mute rule listed | Risk accepted rows listed; false positives counted |
| Remediation tracking | Application Security, triage | Open findings by priority, overdue, fixed in the period, mean time to remediate, reopened; triage status per area | Suppressed findings left out | Overdue leaves out findings closed in triage |
| Licenses | Application Security | Licenses in use with components and targets (latest SBOM per target), categories, license policy violations | Suppressed violations left out | Triage status column |
| SBOM | Application Security | Latest SBOM per target (format, version, components, vulnerable components, vulnerabilities, ecosystems), most vulnerable components with fixed version, ecosystem mix | — | — |

### Finding Status Scope (`status_scope`)

| Value | Failed findings counted and listed |
| --- | --- |
| absent | Failed and not muted: the rule before this change, so existing runs and schedules keep their numbers |
| `active` | Failed, not muted, and with no `risk_accepted` triage row |
| `muted` | Failed and muted |
| `accepted` | Failed with a `risk_accepted` triage row, muted or not |
| `all` | Every failed finding |

The scope shows on the PDF cover ("Finding status"), in the methodology appendix, in the Excel summary (`Filter: status_scope`), in the JSON `filters`, and in the in-app report header. With a scope the findings table gains an Exception column (Active, Muted, Risk accepted) and the KPIs add `status_scope` and `risk_accepted_findings`. A grade is given for absent and `active` only. The UI form offers the field on findings reports and sends `active` by default.

Application Security also exports findings as CSV and JSON from each workspace, SBOMs as CycloneDX or SPDX, and stored scan reports as JSON, SARIF, CycloneDX or SPDX.

## Coverage Against the Request

| Requested | State |
| --- | --- |
| Executive security report, cloud posture, compliance, findings | Covered |
| Resource inventory, attack path report, scan comparison | Partial: in-app pages and the compliance scan comparison; no report type |
| Application Security executive | Partial: the executive report has an application section |
| Vulnerability, SCA, SAST, container, IaC, secrets | Covered |
| License compliance | Covered: `licenses` report |
| SBOM inventory and SBOM vulnerability | Covered: `sbom` report, plus SBOM download per scan |
| Application inventory, scan history | Partial: pages and CSV export; no report type |
| Remediation tracking | Covered: `remediation` report (application lifecycle; cloud and governance through triage status only) |
| Suppression and exceptions | Covered: `exceptions` report and `status_scope` on findings reports |
| Governance executive, policy compliance, policy violations | Partial: governance report only |
| Unified enterprise reports | Partial: executive report only |

## Defects

| ID | Defect | Effect | Next step |
| --- | --- | --- | --- |
| RC-001 | Governance report hard-coded `muted: 0` | Muted governance findings (now possible, PI-012) counted as open | **Fixed**: `muted_resources` KPI; the executive report subtracts it from governance open issues (`test_reports_data.py`) |
| RC-002 | No finding status filter (active, muted, accepted) | Reports cannot separate suppressed from active | **Fixed**: optional `status_scope` on the six findings reports (not a common parameter: other reports reject it) (`test_report_coverage.py::TestStatusScope`, `test_reports_catalog.py`) |
| RC-003 | No exceptions report | Auditors cannot list what was muted or accepted, by whom, until when | **Fixed**: `exceptions` report over `MuteRule` and `FindingTriage` (`test_report_coverage.py::TestExceptionsReport`) |

### Limits of the New Reports

* A mute rule has no provider. When a report is limited to providers (always the case for a limited role), a rule is listed only if one of its UIDs belongs to an in-scope provider's findings, triage rows or application findings; governance UIDs with no triage row are not matched.
* Remediation tracking reads the lifecycle of application findings only. Cloud and governance findings have no due date or fix timestamp; they appear through their triage status.
* License and SBOM reports read the newest SBOM per target (created inside the date window when one is set). The license category per license comes from license findings or `summary.license_categories` when an inventory stores it.

## Verification of Totals

Report totals and dashboard tiles both count FAIL, unmuted findings of the latest scans (`reports/data/common.py` and `GET /area-findings`). Alerts now use the same rule (PI-005). A live comparison on the deployed tenant is in [E2E Test Results](E2E_TEST_RESULTS.md).
