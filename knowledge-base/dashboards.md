# Product Dashboards

How the signed-in home splits into dashboards, where every number comes from, and what the APIs cannot answer yet. Started 2026-11-09. Visual rules are in `design-system.md`.

## Structure

| Dashboard | Route | Purpose | Sidebar |
| --- | --- | --- | --- |
| Overview | `/` | Executive summary of the whole platform. Links to the three area dashboards for detail. | Top, first item |
| Cloud Security | `/cloud-security` | Cloud posture detail: the upstream Overview widgets (threat score, check findings, severity, resources, compliance and service watchlists, attack surface, findings over time, risk pipeline) with provider, account and group filters. | CLOUD SECURITY, first item |
| Application Security | `/application-security` (Dashboard tab) | Repositories, images, code, IaC, secrets, SBOMs and clusters. | APPLICATION SECURITY, first item |
| Cloud Governance | `/governance` (Dashboard tab) | Compliance frameworks, controls, cloud policies, audit and risk decisions. | GOVERNANCE, first item; Compliance follows it |

The Overview is the upstream page with one hook (`upstream-hooks.md`, "Product dashboards"); the flag is `executiveOverview` in `ui/cloudsneeker/features.ts`. Turning it off restores the upstream Overview and puts Compliance back under Cloud Security.

## Where each number comes from

No dashboard computes a metric a second time. Shared readers are in `ui/cloudsneeker/lib/dashboard-data.ts` (server) and the arithmetic in `ui/cloudsneeker/lib/dashboards.ts` (pure, unit tested).

| Figure | Source | Used on |
| --- | --- | --- |
| Overall posture score, area grades, top risks, open issues over time | Latest completed executive report run (`RiskOverview`) | Overview |
| Cloud accounts, connected | `GET /providers` | Overview, Governance |
| Failed cloud checks by severity | `GET /overviews/findings_severity` | Overview |
| Compliance score, frameworks, requirements passed / failed / manual | `GET /overviews/compliance-watchlist` (all frameworks of the latest scans; ThreatScore left out). Score = passed / total requirements, the same formula as the Compliance page cards. | Overview, Governance |
| Passed and failed checks per provider | `GET /overviews/providers` | Governance |
| Open application findings, critical | `GET /area-findings?filter[area]=application_security` counts | Overview |
| Application findings by severity | `GET /findings` on each target's latest completed scan (existing hub calculation) | Application Security |
| Open findings with / without a fix | `GET /area-findings` with `filter[fix]` (existing fixes card); their sum is the open total | Application Security |
| Remediation progress, risk decisions | `GET /area-findings` counts per `filter[triage_status__in]` | Application Security (application area), Governance (cloud area) |
| Targets with findings, findings by repository, image targets, riskiest targets, findings per day | Application scan runs (`GET /trivy-runs`, newest 100): latest completed run per target and its `summary.finding_count` | Application Security |
| Findings by scan type | Existing category summary (`buildAppSecurityDashboard`) | Application Security |
| Policies, dry-runs, resources matched, top policies, resource-match trends | Existing policy dashboard (`buildCustodianDashboard`) | Governance ("Cloud policies") |
| Critical findings needing attention | `GET /area-findings` critical, cloud and application areas, newest sighting first | Overview |
| Recent activity | Cloud scans, application scan runs and policy dry-runs, merged newest first | Overview; failed application scans on Application Security |

Every widget shows "—" or a "could not be loaded" message when its request fails, never a zero. Loading states are skeletons (`Suspense`), empty states use `EmptyState`.

## Drill-downs

- Severity tiles and bars open the matching findings list (`/findings` or the area findings page) with the severity filter.
- Triage bars open the area triage page on that status.
- Targets open their target page; scans and dry-runs open the run.
- Frameworks open Compliance; providers open Findings filtered by provider type.
- KPI tiles open the list they count.

## Not available yet (missing API data)

These requested metrics are not shown because no API returns them. Each needs backend work before a widget can show it.

| Requested | What is missing |
| --- | --- |
| Risk by environment (Development, Staging, Production) | No environment field on providers, targets or findings. Needs an environment tag on providers/targets and an `area-findings` filter. |
| Overdue remediation items | No due date or SLA on findings or triage. Needs an SLA policy per severity or a due date on triage. |
| Newly discovered and resolved vulnerabilities over a date range | `area-findings` has no `first_seen_at` / `last_seen_at` range filter; resolution is only the triage status. Needs date-range filters. |
| Compliance score over time, framework trends | The compliance watchlist returns the latest scans only. Needs a per-scan or daily compliance history endpoint. |
| Not applicable controls | Compliance overviews return passed, failed and manual only. |
| Control ownership, missing controls, control effectiveness | No owner or control catalog model outside the framework JSON. |
| Container image compliance status | Image scans report findings, not a pass/fail policy per image. |
| Date-range and provider filters on the Application Security and Governance dashboards | The area findings, compliance watchlist and run APIs used there take no date range; provider filters exist on Cloud Security. |
