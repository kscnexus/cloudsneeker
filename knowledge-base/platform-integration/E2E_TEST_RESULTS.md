# E2E Test Results

## Local (Windows development machine, 2026-11-11)

The machine has no test database and no Docker, so database tests and async MCP tests run in CI only ([Local test environment notes](../local-development.md)).

| Suite | Command | Result |
| --- | --- | --- |
| API, no database: alerts, conditions, report catalogue | `pytest --noconftest` with stand-in `fcntl`/`resource` | 69 passed |
| API, mute and governance (no-database parts) | same | passed |
| API imports, routes, `makemigrations --check` | Django setup script | No missing migrations; `area-findings/mute` resolves |
| MCP tool registration | import the root server, list tools | 54 tools, the five new ones present |
| UI unit: cloudsneeker, (cloudsneeker) pages, alerts, compliance, mutelist, Seeker AI, compliance components | `vitest run ...` | 1098 passed, 3 failed: `shared-reports/[token]/page.test.tsx` timeouts at 5 s, a known cold-run flake on this machine, unrelated |
| UI type-check | `tsc --noEmit` | Clean |
| Brand audit | `brand_audit.py --source` | 0 hits |

## CI

| Run | Result |
| --- | --- |
| Pull request: "Cloudsneeker: Tests" (SDK, API with database, UI, MCP) | First run: 3 failures (an upstream mute test patched `transaction.on_commit` with a one-argument stand-in that the new signal reached; a duplicate rule name in `test_alert_areas`; the new `area` tool argument lacked the blank guard). Fixed in `fix(platform)`. Two reruns failed only in "Render assessment report samples" because `security.ubuntu.com` did not resolve on the runner; the third passed |
| `main` after merge (`10005697`) | Tests, brand gate and "Deploy to Azure" passed on 2026-11-11 |
| PR #5, #6, #8 (compliance) | Passed; #5 needed one rerun of "Build api image" (Debian mirror sync) |
| PR #7 (alert history) | First run: every API test errored in database setup because the RLS constraint was created inside `CreateModel`; fixed with `AddConstraint`. Second run passed (API, UI) |
| `main` after #7 and #8 (`be1c0b75`) | Tests passed, "Deploy to Azure" completed on 2026-11-12; `/api/v1/alerts/events` answers 401 unauthenticated (route live) |

## Deployed Site Scenarios

Run on https://cloudsneeker.vercel.app on 2026-11-11 after the merge, signed in as the tenant owner.

| Scenario | Steps | Status |
| --- | --- | --- |
| Compliance | Sidebar Compliance → Single Scan; Provider lists cloud then SaaS, no code or image providers; Account narrows the scan list; frameworks match the provider | Verified with AWS scan `01a1b683` (Provider, Account, Scan selectors, ThreatScore, 49 frameworks). Fixed in #5 (PI-027), see below. Before the fix: scan `01a1c06a` (4,628 resources, finished near a VM restart) raises a server error on the page, and it is the default scan, so plain `/compliance?tab=per-scan` shows the error page. The page-level scan list is the same for every scan, so the failure is in that scan's compliance data calls; API logs are needed |
| Multiple Scans | `/compliance` (Multiple Scans) | Verified 2026-11-12 after #5, #6, #8: compares two AWS scans with results, no "Removed" rows, no notice |
| Compliance, failed scan | `/compliance?tab=per-scan&scanId=01a1c06a-…` | Verified after #5: the "Compliance results are not available for this scan" notice instead of the error page; the default opens a scan with frameworks |
| Alert history | `/alerts?tab=history`, filters Status = Open, Module = Cloud Governance, search | Verified 2026-11-12: Rules and History tabs; filters reach the API; empty state (the tenant has no alert rules, so no event exists yet) |
| Global search (#12) | `/search?q=bucket` | Verified 2026-11-12: 1188 Cloud Security findings, 1 Application Security finding, 2 targets, links and "See all"; the first try showed "Token is invalid" while the session token refreshed, a reload worked |
| Governance finding detail (#11) | `/governance/findings/custodian-…-averytestdb` | Verified: resource, policy, rule, run link, dates, triage link, Mute, raw resource record |
| Frameworks across accounts (#13) | `/compliance?tab=cross-provider&view=accounts` | Verified: AWS · 1 account, 49 frameworks, 25% of 5895 requirements passed, most failed first |
| Select all matching (#9) | `/governance/findings`, select the page | Verified the bar ("1 selected on this page"); "Select all matching" is not offered because every governance finding fits on one page; the cross-page path is covered by component tests |
| Reports (#15) | `/reports` catalogue; generate Exceptions | Verified 2026-11-12: Exceptions, Remediation tracking, Open-source licenses and Software bill of materials listed; an Exceptions PDF generated (34 KB, "no exceptions in scope" on this tenant). The first load after the deploy showed "Reports are not available right now" while the API restarted |
| Uptime monitoring (#14) | "Cloudsneeker: Uptime" run on demand | Passed (API liveness, API authentication, web app sign-in) |
| Alerts | `/alerts` → New alert → Modules = Application Security → Test shows only application counts; rule list shows the module | Verified: New alert, Modules selector, Test returned 8,597 findings. No rule saved (tenant has no alert rules) |
| Application Security alert | Rescan a target with an Application Security rule enabled; notification links to the scan run | Needs a confirmed recipient or Slack channel on the tenant |
| Governance alert | Run a policy dry run with a governance rule enabled | Needs a confirmed recipient or Slack channel |
| Mute | Mute an application finding with a reason; it leaves the workspace, the detail shows the rule; it appears on the Mutelist page | Pending deploy |
| Governance mute | Mute a governance finding from `/governance/findings`; it leaves the list | Pending deploy |
| Governance lists | Policies and Reports tabs: search, account, status, paging | Verified: search "access" returned 5 policies; Reports shows the account and status filters and 2 dry runs |
| Targets list | Search, target type, paging over the tenant's 318 targets | Verified: "318 targets · Page 1 of 13" with Next |
| Seeker AI | The questions in [Seeker AI Cross-Module Audit](SEEKER_AI_CROSS_MODULE_AUDIT.md) | Needs a working model key on the tenant (credits were exhausted on 2026-10-29) |
| RBAC | Read-only role sees governance policies of its provider groups only | Needs a second user; not created on the public site (security rule) |

## Governance Policy Run (2026-11-12)

All test records are kept (policies, runs, the alert rule "Governance policy test alert", the mute rule, reports).

| Step | Result |
| --- | --- |
| Policies | 17 Critical and High library policies added; 46 AWS policies on account 466920982015 |
| Dry runs | All 46 run: 43 completed (385 findings before fixes), 1 failed on AWS permissions (`lambda:GetFunctionUrlConfig` missing from the scan role for "Lambda function URLs without auth"), 2 S3 policies timed out after 900 s |
| Fixes (PR #18) | Library severity carried into findings; security group, VPC, Elastic IP and other findings no longer dropped (453 findings: 36 Critical, 349 High, 132 Medium, 58 Low by report); global resources (S3, IAM, CloudFront, Route 53) run in one region, S3 now 1 minute and 28 public buckets; failed runs show the cloud API error |
| Select all matching (#9) | "Select all 385 matching" selected 385 across pages; no bulk change applied |
| Search | "deprecated" 136 governance findings |
| Detail page | Resource, policy, run link, raw resource, Mute |
| Mute | Muted one Lambda finding with a reason; open count 136 to 135; rule on the Mutelist page; Exceptions report lists it |
| Alert history | Rule "Governance policy test alert" (Cloud Governance, Critical and High by default): events for SSH open (59 High) and Public S3 buckets (28 Critical), "not delivered" (no destination); Acknowledge with a note recorded who and when; status filter works |
| Governance report (PR #20) | Severity breakdown and severity-ranked top risks; muted resources KPI 1 |
| Alert form (PR #19) | Says that no severity means Critical and High |
| Sessions (PR #21, #22) | Users were signed out mid-session (68 failed token refreshes beside 2 good ones); refresh grace window deployed (`CLOUDSNEEKER_REFRESH_GRACE_SECONDS=60` on the VM); 8 parallel page loads after the deploy all 200. The VM build hang at BuildKit export (twice) now times out after 10 minutes and retries |
