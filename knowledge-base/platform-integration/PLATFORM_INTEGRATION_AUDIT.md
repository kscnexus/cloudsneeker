# Platform Integration Audit

Started 2026-11-11. This audit checks how Cloud Security, Application Security and Cloud Governance connect to the shared platform operations: findings, alerts, mutelist, reports, Seeker AI, filters, compliance, RBAC and navigation. It records each defect found, its cause, its fix and its verification state.

Companion documents in this folder:

| Document | Covers |
| --- | --- |
| [Module Integration Matrix](MODULE_INTEGRATION_MATRIX.md) | Every shared capability per module, with the state after this work |
| [Report Coverage Audit](REPORT_COVERAGE_AUDIT.md) | Report catalogue against the requested coverage |
| [Seeker AI Cross-Module Audit](SEEKER_AI_CROSS_MODULE_AUDIT.md) | What the assistant can read per module, and how it uses page context |
| [RBAC and Tenant Isolation Audit](RBAC_AND_TENANT_ISOLATION_AUDIT.md) | Permissions and tenant scoping per endpoint family |
| [UX and Navigation Audit](UX_AND_NAVIGATION_AUDIT.md) | Navigation, lists, filters and empty states |
| [E2E Test Results](E2E_TEST_RESULTS.md) | Tests run, where, and their results |
| [Deployment and Rollback](DEPLOYMENT_AND_ROLLBACK.md) | Release path, migrations, rollback |
| [Implementation Changelog](IMPLEMENTATION_CHANGELOG.md) | Commits of this work and what each changed |

## How the Modules Store Findings

The three modules do not share one finding table, so every shared operation has to handle three shapes. This is the root cause of most defects below.

| Module | Engine | Stored as | Finding UID |
| --- | --- | --- | --- |
| Cloud Security | Posture checks | Upstream `Scan` and `Finding` rows | Upstream `Finding.uid` |
| Application Security | Scan engine and static analysis | `AppSecFinding` (lifecycle, one row per fingerprint and target) plus shared `Finding` rows on a `Scan` with `scanner_args.source = "trivy_hub"` | `trivy-<mode>-...` or `opengrep-sast-...` |
| Cloud Governance | Policy dry runs | `CustodianRun.output["resources"]`; no `Finding` rows | `custodian-<policy id>-<resource id>` |

The shared read layer is `GET /area-findings?filter[area]=...` (`cloudsneeker_api/services/area_findings.py`). It normalizes all three to one row shape and keeps the module in `area`. This work routes alerts, muting and Seeker AI through the same area model.

## Definitions

Used by alerts, area lists, the posture summary tool and the documents in this folder.

| Term | Definition |
| --- | --- |
| Open finding | Status FAIL, not muted, in the latest completed scan of its cloud account, application target or governance policy |
| Unique finding | One finding UID. A UID seen in many scans is one finding |
| Muted (suppressed) finding | A finding whose UID is in an enabled mute rule, or an application finding the scanner's ignore rules suppressed. It stays stored and readable; it leaves the open views and does not alert |
| Fixed finding | Application Security: lifecycle state `fixed`, set only by a complete scan that no longer reports it. Cloud: a later scan reports PASS |
| Accepted risk | Triage status `risk_accepted`, with a reason and an expiry |
| Reopened finding | Triage `resolved` and failing again in a newer scan, or application lifecycle state `reopened` |
| New finding | Cloud: `delta = new`. Application Security: lifecycle state `new`. Governance: first seen equals last seen |

## Issues

Status values: Identified, In Progress, Fixed, Tested, Deployed, Verified, Blocked. "Tested" means the unit tests that run without a database passed locally; tests that need a database run in CI.

| ID | Module | Description | Root cause | Impact | Fix | Tests | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PI-001 | Alerts, all | An alert rule could not say which module it watches | The condition language had no area field | A cloud rule also fired on application findings, labelled as cloud | `area` leaf field (`cloud`, `application_security`, `governance`) in `alert_conditions.py`; Modules selector in the rule form; Modules column in the list | `test_alert_areas.py`, `alert-areas.test.ts` | Tested |
| PI-002 | Alerts, Application Security | Application scans never evaluated alert rules | The scan engine writes `Scan`/`Finding` rows directly and never called the alert task; only the provider scan did | No alert for any repository, image or code scan | `appsec/engine.persist_results` queues evaluation after commit | `test_alert_areas.py::TestEvaluateRules` (CI) | Fixed |
| PI-003 | Alerts, Governance | Governance policy runs never raised alerts | Governance has no `Finding` rows; the evaluator only read `Finding` | No governance alerting at all | In-memory evaluator over governance findings; policy runs queue evaluation; only rules that name the governance area see them | `test_alert_areas.py` | Tested (CI for DB part) |
| PI-004 | Alerts | "Daily" and "After each scan and daily" rules never ran daily | No task read the `daily` trigger | Daily digests were silently never sent | Beat task `cloudsneeker-evaluate-daily-alert-rules` (migration `0026`) evaluates the latest scan per account and target and the latest run per policy | `test_alert_areas.py::test_daily_uses_latest_scan_per_provider` (CI) | Fixed |
| PI-005 | Alerts, data accuracy | Rules counted passed checks and muted findings | The queryset was every `Finding` of the scan | Inflated counts; muted findings still alerted | Only FAIL and unmuted findings can match | `test_alert_areas.py` | Fixed |
| PI-006 | Alerts, navigation | Every link from Alerts went to the cloud Findings page; notifications had no link | Fixed `/findings` strings; body was only "matched N findings" | Application and governance alerts opened Cloud Security | Notifications list the count per module with links to the cloud scan findings, the application scan run, or the governance policy run | `test_alert_areas.py::test_body_names_each_area_with_its_links` | Tested |
| PI-007 | Alerts | Rule test counted every finding of every scan | Preview queried all tenant findings | "Test" showed numbers far above the dashboard | Preview reads the latest scans, FAIL and unmuted, split by module | covered by PI-005 tests | Fixed |
| PI-008 | Alerts | A rule created from Findings filters kept only severity | `seed` read severity and dropped the rest | Provider, region, service and check filters were lost | `seed_condition` keeps every filter the condition language knows, plus area | `test_alert_areas.py::TestSeedAndMessage` | Tested |
| PI-009 | Mutelist, Application Security | Application rescans ignored mute rules | Upstream applies rules inside the provider scan only | A muted dependency came back unmuted on the next scan | `area_mute.reconcile_scan` after every application scan | `test_area_mute.py::test_rescan_applies_enabled_rules` (CI) | Fixed |
| PI-010 | Mutelist, Application Security | Creating a mute rule muted only one application target | Upstream mutes "the latest scan of each provider"; hundreds of targets share one provider | Most targets kept showing the finding | A rule change mutes the latest scan of every target (`sync_rule`, via a `MuteRule` signal) | `test_area_mute.py` (CI) | Fixed |
| PI-011 | Mutelist, Application Security | Application posture pages ignored the mutelist | `AppSecFinding.suppressed` only reflected scanner ignore rules | Muted findings stayed in vulnerability, secret and license workspaces | Posture rows follow enabled rules; released when the rule goes; the detail page names the rule and reason | `test_area_mute.py` (CI) | Fixed |
| PI-012 | Mutelist, Governance | Governance findings could not be muted | Upstream `mute-rules` takes `Finding` ids; governance has none | No suppression for policy violations | `POST /area-findings/mute` stores governance UIDs in an upstream rule; the governance list hides them unless muted findings are included | `test_area_mute.py::test_governance_findings_can_be_muted` (CI) | Fixed |
| PI-013 | Mutelist, UI | No mute action outside the cloud Findings page | Not built | Users had to mute application findings from the cloud page | Mute in the bulk bar of the area findings tables and on the application finding detail; reason required | type-check, `area-findings-table.test.tsx` | Tested |
| PI-014 | Compliance, navigation | Compliance opened on Multiple Scans | Upstream makes Multiple Scans the bare route | Users landed on a comparison instead of the scan configuration flow | Sidebar Compliance opens Single Scan (`/compliance?tab=per-scan`) | `navigation.test.ts` | Tested |
| PI-015 | Compliance | Single Scan had no provider or account step; the scan list mixed code and image scans and could be filled by them | The page took the newest 50 scans of any provider | Cloud scans disappeared from the list once many application scans ran; frameworks looked unrelated to a provider | Provider (cloud first, SaaS grouped), then account, then scan; scans fetched by provider type | `single-scan-scope.test.ts`, compliance suite | Tested |
| PI-016 | Compliance (Cloud edition only) | Cross-provider framework grid ignores the provider type filter | `loadCrossProviderFrameworks` returns every framework | Not active in this deployment (`UI_CLOUD_ENABLED=false`) | Not changed: upstream code, unused here | — | Identified |
| PI-017 | Governance, RBAC | Reading policies and runs needed `manage_scans`, and a role limited to some providers saw every policy | Viewsets required `manage_scans` for all actions and did not filter by provider | Read-only users were locked out; limited roles saw other accounts' policies | Reads follow provider visibility; writes still need `manage_scans` | `test_governance_access.py` (CI) | Fixed |
| PI-018 | Governance, UX | Policies and dry-run lists stopped at 100 rows with no search | One page of 100 | Policies past 100 were invisible | Search, account and status filters, 25 per page, URL state | `list-filters.test.ts` | Tested |
| PI-019 | Application Security, UX | Targets were one endless list; a truncated load was not shown | Flat list of every target | Hundreds of targets to scroll | Search, target type filter, 25 per page, truncation notice; connected repositories show ten and a count | `list-filters.test.ts` | Tested |
| PI-020 | Seeker AI | No tool could read Application Security or Governance data | Only upstream cloud tools were allowlisted | Answers about applications or policies had no data | Five read-only MCP tools, allowlisted | `mcp_server/tests/cloudsneeker/test_area_tools.py` (CI) | Fixed |
| PI-021 | Seeker AI | Prompt was cloud-only; no rule for the selected application finding | Upstream prompt | "How do I fix this?" on an application finding had no context | Prompt names the modules, the page-path rule and the source and recommendation rules | `lighthouse-prompt.test.ts` | Tested |
| PI-022 | Reports | No license, SBOM, remediation tracking, or suppression/exception report; no finding status filter; the governance report shows muted as 0 | Not built | Gaps against the requested catalogue | See [Report Coverage Audit](REPORT_COVERAGE_AUDIT.md) | — | Identified |
| PI-023 | Alerts | Alerts are rules, not alert records: no acknowledge, resolve, history | No alert event model | Cannot track an alert's lifecycle | Design in the matrix document; needs a new table | — | Identified |
| PI-024 | Navigation | No global search | Not built | Users browse module by module | Design note in [UX and Navigation Audit](UX_AND_NAVIGATION_AUDIT.md) | — | Identified |
| PI-025 | Governance | No detail page per governance finding | Not built | Links fall back to a search, or the policy run page (alerts) | Alerts link to the policy run, which lists the matched resource | — | Identified |
| PI-026 | Lists | Area table "select all" covers the visible page only, without saying so | Label | A user could think every result was selected | Bar now says "N selected on this page" | `area-findings-table.test.tsx` | Tested |
| PI-027 | Compliance | Single Scan showed the error page for a scan whose compliance task failed, and that scan was the default | `compliance-overviews/metadata` answers 500 "Task failed to generate compliance overview data" by design; the page let the error escape | Compliance unreachable from the sidebar | Default skips scans whose metadata fails (up to 5 tried); a URL scan shows a notice with a link to Scans | `scan-availability.test.ts`, `load-compliance-metadata.test.ts`, upstream `page.test.tsx` | Fixed |
| PI-028 | Compliance | Multiple Scans showed "No Scans available" | It read the newest 50 completed scans, all Application Security, then dropped them | Comparison unusable | Same provider filter as Single Scan (`complianceScanFilters()`) | upstream `page.test.tsx` | Fixed |

## What Was Not Changed

* Upstream checks, migrations and API types.
* The bare `/compliance` route still opens Multiple Scans (upstream default; upstream tests assert it). Every Cloudsneeker entry point opens Single Scan.
* Alert records with acknowledge and resolve (PI-023): needs a model and is a feature, which the brief puts on hold.
