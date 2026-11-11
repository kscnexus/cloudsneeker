# Report Coverage Audit

Catalogue read from `api/src/backend/cloudsneeker_api/reports/catalog.py` on 2026-11-11. Every report type renders PDF, Excel, CSV and JSON. Common parameters: providers, date range, severity floor, trend points; compliance also takes a framework and scan. All data comes from database queries (`reports/data/*.py`); nothing is static.

## Catalogue

| Report | Module | Data | Muted findings | Triage |
| --- | --- | --- | --- | --- |
| Executive | Cross-module | Cloud, application, compliance, governance scores | Counted separately (`muted_findings`) | In progress, resolved, false positive, risk accepted counts |
| Cloud posture | Cloud Security | Findings, services, trend | Counted, excluded from tables | — |
| Compliance | Cloud Security | Framework requirements for a scan | — | — |
| SCA | Application Security | Dependency findings, exploitation column | Counted, excluded | — |
| SAST | Application Security | Code findings | Counted, excluded | — |
| Container | Application Security | Image findings | Counted, excluded | — |
| IaC | Application Security | Misconfigurations | Counted, excluded | — |
| Secrets | Application Security | Secret findings | Counted, excluded | — |
| Governance | Cloud Governance | Dry-run matches per policy, new and resolved deltas | `muted_resources` KPI (RC-001); executive open issues exclude them | — |

Application Security also exports findings as CSV and JSON from each workspace, SBOMs as CycloneDX or SPDX, and stored scan reports as JSON, SARIF, CycloneDX or SPDX.

## Coverage Against the Request

| Requested | State |
| --- | --- |
| Executive security report, cloud posture, compliance, findings | Covered |
| Resource inventory, attack path report, scan comparison | Partial: in-app pages and the compliance scan comparison; no report type |
| Application Security executive | Partial: the executive report has an application section |
| Vulnerability, SCA, SAST, container, IaC, secrets | Covered |
| License compliance | Gap: data exists (`AppSecFinding` category `license`), no report type |
| SBOM inventory and SBOM vulnerability | Partial: SBOM download per scan; no report type |
| Application inventory, scan history | Partial: pages and CSV export; no report type |
| Remediation tracking | Gap: deadlines and lifecycle exist on `AppSecFinding`; no report type |
| Suppression and exceptions | Gap: muted findings are counted, never listed; risk acceptances are not listed |
| Governance executive, policy compliance, policy violations | Partial: governance report only |
| Unified enterprise reports | Partial: executive report only |

## Defects

| ID | Defect | Effect | Next step |
| --- | --- | --- | --- |
| RC-001 | Governance report hard-coded `muted: 0` | Muted governance findings (now possible, PI-012) counted as open | **Fixed**: `muted_resources` KPI; the executive report subtracts it from governance open issues (`test_reports_data.py`) |
| RC-002 | No finding status filter (active, muted, accepted) | Reports cannot separate suppressed from active | Add a `status_scope` parameter to `COMMON_PARAMS` |
| RC-003 | No exceptions report | Auditors cannot list what was muted or accepted, by whom, until when | New report type over `MuteRule` and `FindingTriage` (`risk_accepted`, `false_positive`) |

RC-002 and RC-003 are report features rather than integration fixes; they are listed for the next iteration and were not built here.

## Verification of Totals

Report totals and dashboard tiles both count FAIL, unmuted findings of the latest scans (`reports/data/common.py` and `GET /area-findings`). Alerts now use the same rule (PI-005). A live comparison on the deployed tenant is in [E2E Test Results](E2E_TEST_RESULTS.md).
