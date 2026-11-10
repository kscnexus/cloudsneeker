# Application Security redesign

Audit of the Application Security module (November 2026) and the target
architecture it moves toward. Each phase ships on its own and is checked
before the next starts.

## What exists today

| Route | Purpose | Data |
| --- | --- | --- |
| `/application-security` | Tabs: Dashboard, Targets, Scans. Dashboard has KPI cards, fixable findings, insights, connected repositories without a target. Scans has history grouped by target plus the archive | `/trivy-targets`, `/trivy-runs`, `/findings`, `/providers` |
| `/application-security/new`, `/[targetId]/edit` | Create or edit a target (mode, scanners, schedule) | `/trivy-targets` |
| `/application-security/[targetId]` | One target: config, runs | `/trivy-targets/{id}`, `/trivy-runs` |
| `/application-security/[targetId]/runs/[runId]` | One run: summary, error | `/trivy-runs/{id}` |
| `/application-security/findings` | Current findings of the latest completed run per target, with severity, triage, target, search, fix and exploited filters, bulk triage | `/area-findings?filter[area]=application_security` |
| `/application-security/triage` | Findings with a triage record, by status | `/finding-triages` |

Data model:

* `TrivyTarget`: one scan target (mode `repo`, `fs`, `image`, `iac`, `sbom`, `k8s` or `sast`), linked to a Prowler `Provider`.
* `TrivyRun`: one execution. Findings live in Prowler `Scan` and `Finding` rows (`TrivyRun.scan_id`).
* `FindingTriage`: status (open, under review, in progress, resolved, risk accepted, false positive), assignee, notes and risk acceptance. It is keyed by finding uid, so it follows a finding across rescans.

## Problems found

1. **No security category.** Findings were only grouped by target and severity, so SAST, dependency, secret, IaC and container issues sat in one list. Fixed in phase 5 (below).
2. **Targets are mixed with applications.** There is no application entity. A repository's code, image and SAST targets are separate rows with no grouping.
3. **Scans and findings overlap on the hub page.** The Dashboard tab shows recent runs and finding KPIs side by side. The Scans tab now groups history but has no scanner filter.
4. **Finding detail is an inline expander.** There is no shareable page per finding.
5. **No priority.** Severity, EPSS and CISA KEV exist but are not combined into a priority.
6. **Empty categories are invisible.** Nothing told a user that DAST or API testing is not integrated.

## Target architecture and mapping

| New section | Built from | Status |
| --- | --- | --- |
| Overview | Dashboard tab of `/application-security` | Exists; to be trimmed to posture, distribution and drill-downs |
| Application Inventory | Targets tab, grouped by linked provider (repository) | Planned: group targets by `provider_id`; no new model needed for a first version |
| Security Findings | `/application-security/findings` | **Category dimension shipped** |
| Finding detail | Inline expander in the findings table | Planned: route keyed by finding uid |
| Security Scanning | `/[targetId]` and `/[targetId]/runs/[runId]` | Exists per target; planned: one runs list with category and status filters |
| Component Inventory | Not supported | Needs SBOM/package storage; vulnerability rows only carry the vulnerable package |
| Remediation & Risk | `/application-security/triage` plus risk acceptance | Exists; due dates and validation by rescan are planned |
| Scan History | Scans tab: 20 per target plus the yearly archive | Exists |
| Reports | `/reports` (shared) | Exists outside the module |

## Security categories (phase 5, shipped)

`cloudsneeker_api/services/app_security_categories.py` puts each finding in exactly one category, so category counts add up to the finding total:

| Category | Rule |
| --- | --- |
| `secrets` | raw result has `RuleID` and `Match` |
| `sast` | raw result has `extra` (static analysis output) |
| `container` | a vulnerability from an `image` or `k8s` target, or a misconfiguration from an `image` target |
| `sca` | any other package vulnerability, or a license result |
| `iac` | everything else (misconfigurations) |

API: `GET /area-findings?filter[area]=application_security&filter[category__in]=sca,secrets`. The response adds `meta.category_counts`, which counts under every filter except the category filter, and `meta.enabled_categories`, the categories some visible target is set up to report. The value per row is `security_category`.

UI: `SecurityCategoryTabs` on the findings page shows All plus one tab per category with its count. A category no target runs shows "Not enabled". DAST and API testing are listed as not integrated. The table has a Category column.

## Limitations

* No DAST or API security scanner is integrated. They are shown as not integrated, never as empty results.
* Environment, business owner, technology stack and branch are not stored. They stay hidden until a field exists.
* Finding status "Confirmed" and "Reopened" have no backend transition. Triage statuses are used as they are.
