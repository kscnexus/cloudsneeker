# Area Findings and Triage

Started 2026-11-02. Cloudsneeker has three product areas: Cloud Security, Application Security and Cloud Governance. They stay separate sidebar sections with separate pages. One shared Findings and Triage experience (one API, one set of UI components) serves all three. Each area gets its own Findings page and its own Triage page, scoped to that area's data.

The upstream Findings page (`/findings`) and its API, filters and migrations are unchanged. Cloud Security keeps it as the detailed cloud findings view.

## Where Each Area's Findings Come From

| Area | Engine | Stored as | Finding UID |
| --- | --- | --- | --- |
| Cloud Security | Prowler checks | Upstream `Scan` / `Finding` rows. Scans whose `scanner_args.source` is not `trivy_hub` | Upstream `Finding.uid` |
| Application Security | Trivy, OpenGrep (SAST) | Upstream `Scan` / `Finding` rows written by `trivy_import`, with `scanner_args {"source": "trivy_hub", "mode": ...}`. `TrivyRun.scan_id` links a run to its scan | `trivy-<mode>-...` or `opengrep-sast-...` (`trivy_import.py`) |
| Cloud Governance | Cloud Custodian (dry run) | `CustodianRun.output["resources"]` (JSON, at most 500 per run, trimmed by a periodic task). No `Finding` rows | None today. This design adds `custodian-<policy id>-<resource id>` |

## Gap Analysis

What Cloud Security offers today, and whether the other two areas have it.

| Capability | Cloud Security | Application Security | Cloud Governance |
| --- | --- | --- | --- |
| Findings list with filters (severity, status, check, source, date) | Yes, upstream `/findings` | Partial. "Open findings" on a run opens the cloud `/findings` page filtered by scan. Columns are cloud columns (region, service, compliance), so CVE, package, file and line are hidden or misplaced | Partial. Per-run resource table on the run page only. No list across policies, no severity, no filters |
| Finding detail (description, remediation, resource) | Yes, upstream drawer | Same cloud drawer, cloud headers | Raw resource JSON on the run page |
| Triage status and notes (EB-010) | Yes. Inline in `/findings`, list at `/triage` | Works by accident: rows are `Finding` rows, so triage set in `/findings` is stored. `/triage` mixes them with cloud triage | No. Triage requires a `Finding` row with the UID |
| Bulk triage | API only (`finding-triages/bulk`) | API only | No |
| Overview / dashboard | Upstream overview, risk overview | Hub dashboard (KPIs, severity, coverage by mode) | Hub dashboard (policies, runs, matched resources) |
| Compliance mapping | Upstream compliance frameworks per scan | No. CWE and OWASP are stored in `Finding.categories` but not shown as a framework | No |
| Attack paths | Upstream (AWS graph) | No (not applicable to code findings) | No |
| Resources inventory | Upstream `/resources` | Mixed into upstream `/resources` | No |
| Mutelist | Upstream | Not applied to imported rows | No |
| Reports | Cloud posture, compliance, executive | SCA, SAST, containers, IaC, secrets reports | Governance report |
| Alerts | Upstream alert rules | Upstream rules see the rows, labelled as cloud | No |
| Scheduling | Scan schedules | Target schedules | Policy schedules |

## Target Design

### Navigation

Sections stay separate. Each gains a Findings and a Triage entry, gated by the area's plan feature plus `finding_triage` for Triage.

| Section | Items |
| --- | --- |
| Cloud Security | Findings (upstream `/findings`), Triage (`/triage`, now the shared view scoped to cloud), Resources, Attack Paths, Compliance |
| Application Security | Overview (`/application-security`), Findings (`/application-security/findings`), Triage (`/application-security/triage`) |
| Cloud Governance | Overview (`/governance`), Findings (`/governance/findings`), Triage (`/governance/triage`) |

### Shared API

One area-aware layer in `cloudsneeker_api`, used by all three areas.

* `GET /api/v1/area-findings?filter[area]=cloud|application_security|governance` lists the findings of the latest completed scan or run per source in that area, normalized to one shape: `uid`, `title`, `severity`, `status` (fail / pass), `check_id` (rule, CVE or policy), `resource` (name, type, location such as file and line, package, region), `source` (provider, target or policy, with ids), `first_seen_at`, `last_seen_at`, `categories`, `remediation`, and the triage fields (`triage_status`, `triage_id`, `notes_total`). Filters: `severity__in`, `triage_status__in`, `source`, `check_id`, `search`. Sort by severity, last seen, or check. Paginated.
  * Cloud: upstream `Finding` rows, latest scan per provider, excluding `trivy_hub` scans.
  * Application Security: `Finding` rows from the latest completed `trivy_hub` scan per target.
  * Governance: resources of the latest completed run per policy. Severity comes from the policy YAML (`metadata.severity`), default `medium`.
* `FindingTriage` gains an `area` column (Cloudsneeker migration, default `cloud`, backfilled from the UID prefix). Triage list, bulk and UID routes accept `filter[area]` and `area`. Governance triage is validated against the latest run of its policy instead of a `Finding` row. Visibility stays provider-based (`CustodianPolicy.provider`, `TrivyRun.provider`).
* Writes still need `manage_scans`. Every change goes through the existing audit log.

### Shared UI

`ui/cloudsneeker/components/area-findings/` holds the shared pieces. Each area passes an area config: the column set (cloud: check, resource, region, service; application security: rule or CVE, package or file and line, target, mode; governance: policy, resource, type, region), filter options, and labels.

* `AreaFindingsTable`: list with severity, triage status, filters, row selection, and a detail drawer with notes.
* `AreaTriageTable`: the current `/triage` table, generalized by area.
* `AreaBulkTriageBar`: bulk status change on selected rows (closes the "bulk endpoint has no UI" gap from [Finding Triage](finding-triage.md)).

## Phases

| Phase | Scope |
| --- | --- |
| 1 | Shared API (`area-findings`, triage `area`), shared UI, Findings and Triage pages for all three areas, sidebar entries |
| 2 | Area overviews on the shared data: severity trend, top rules, triage progress per area |
| 3 | Compliance mapping for Application Security (OWASP Top 10, CWE Top 25 from `categories`) and Governance (policy-to-control mapping) |
| 4 | Area alerts and area filters on reports |

Attack paths stay Cloud Security only. Code and policy findings have no resource graph to walk.

Decisions (user, 2026-11-02): phase 1 covers all three areas; governance severity comes from the policy YAML (`metadata.severity`), default `medium`.

## Phase 1 (built)

API (`cloudsneeker_api`):

* `services/area_findings.py`: `parse_query`, `scan_sources` (latest completed scan per provider for cloud, latest completed `TrivyRun` per target for Application Security), `list_area_findings` (one page, resources from `ResourceFindingMapping`, triage merged in). Untriaged findings read as `open`; the `open` filter also drops UIDs triaged to another status.
* `services/governance_findings.py`: governance findings from the latest completed `CustodianRun` per policy. UID `custodian-<policy id>-<resource id>` (bounded like the import UIDs). Resource id lookup order matches the run page. First seen is the policy's first completed run.
* `views_area_findings.py`: `GET area-findings`. The area must be in the tenant's plan (`cloud_posture`, `application_security`, `governance`); otherwise `403`. Reading follows provider visibility, like triage.
* `FindingTriage.area` (migration `0018_finding_triage_area`, backfilled from the `trivy-` and `opengrep-` UID prefixes). Writes set it from the finding: `trivy_hub` scans are Application Security, `custodian-` UIDs are Governance, the rest Cloud. `finding-triages` accepts `filter[area]`; the UID routes and bulk resolve governance UIDs against the latest policy run.
* Tests: `tests/test_area_findings.py`.

UI:

* Pages: `/application-security/findings`, `/application-security/triage`, `/governance/findings`, `/governance/triage`. `/triage` is now the shared triage view scoped to `cloud`.
* Shared components in `ui/cloudsneeker/components/`: `AreaFindingsView` (server; filters, pagination, load error), `AreaFindingsFilters` (severity and triage chips, search, source, sort), `AreaFindingsTable` (client; per-row status, bulk status on selected rows, expandable detail with notes; controls only with `manage_scans`), `AreaTriageView`. `FindingTriageTable` and `FindingTriageStatusFilter` take an `area`.
* Helpers: `ui/cloudsneeker/lib/area-findings.ts` (`AREA_CONFIG` column labels per area, filter parsing, API query, links). Types: `ui/cloudsneeker/types/area-findings.ts`.
* Sidebar: each of Application Security and Governance lists its hub, Findings and Triage. Triage pages need `finding_triage` in the plan.

Known gaps:

* Application Security run pages still link "Open findings" to the cloud Findings page filtered by scan (older runs are not in the area list, which shows the latest run per target).
* Governance findings have no remediation text; policies carry none.
* The governance list is built in memory from at most 500 resources per run.

## How to Fix (built)

Each area finding row carries `fix_available`, `fix_summary`, `installed_version`, `fixed_version` and `fix_references`. They come from `cloudsneeker_api/services/finding_fix.py` and are computed when the list is read, so older findings get them too:

| Stored result | Fix |
|---------------|-----|
| Package vulnerability (`raw_result.VulnerabilityID` / `InstalledVersion`) | "Upgrade X from a to b or later." when `FixedVersion` is set; otherwise "No fix yet". |
| Misconfiguration with `Resolution` | The resolution text. |
| Secret (`RuleID` + `Match`) | Revoke, rotate, and remove from the code and history. |
| License (`Name` + `Category`) | Confirm the license is allowed, or replace the package. |
| SAST result (`extra.fix` / `extra.message`) | The code fix, else the rule message. |
| Cloud check | `Remediation.Recommendation` from the check metadata (key case ignored). |

Governance rows have no fix. `filter[fix]=available|unavailable` filters the list. Its database form, `_fix_available_q`, must stay in step with `finding_fix`.

The UI shows a Fix column and a "How to fix" block in the Cloud Security and Application Security findings tables, with "Fix available" / "No fix yet" chips. The Application Security page uses the same Dashboard-style tabs as Cloud Governance (`ProductPageTabs`): Dashboard (KPIs, severity, coverage, a Fixes card with the top fixes, recent scans), Targets (scan-type chips) and Scans.
