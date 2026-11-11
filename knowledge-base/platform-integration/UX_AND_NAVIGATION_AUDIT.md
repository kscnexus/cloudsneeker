# UX and Navigation Audit

Cloud Security is the reference: a filter bar above the table, URL state, server-side pagination, clear empty states.

## Fixed

| ID | Page | Problem | Change |
| --- | --- | --- | --- |
| PI-006 | Alerts | Only route into alerts was the cloud Findings page; no way to create a rule for another module | "New alert" on `/alerts` with a Modules selector; "Create alert" on the Application Security and Governance findings pages (`/alerts?new=1&area=...`); Modules column |
| PI-013 | Area findings, application finding detail | No mute action | Mute with a required reason; the finding shows the rule and reason once muted |
| PI-014, PI-015 | Compliance | Opened on Multiple Scans; Single Scan offered one long scan list across every provider | Sidebar opens Single Scan; Provider (cloud first, SaaS grouped) → Account → Scan → Regions; "Run a new scan" |
| PI-018 | Governance Policies and Reports tabs | One page of 100, no search | Search, account and status filters, 25 per page, "N policies · Page X of Y", empty state that says filters hide results |
| PI-019 | Application Security Scans | Every target in one list; connected repositories listed in full | Search, target type, 25 per page, truncation notice; ten repositories and a count |
| PI-026 | Area findings bulk bar | "N selected" without scope | "N selected on this page" |

Shared pieces added: `ui/cloudsneeker/lib/list-filters.ts` (parse, link, query, in-memory filter and page helpers) and `ui/cloudsneeker/components/list-filter-bar.tsx` (`ListFilterBar` GET form and `ListPager`). They need no client JavaScript, keep state in the URL and reset to page 1 on every change.

## Open

| Item | Notes |
| --- | --- |
| Global search (PI-024) | `cmdk` is already a dependency. A command palette over `area-findings` (all three areas), providers, targets, policies and reports, each result tagged with its module and linked with the module's own helper (`areaFindingHref`), would need no new API. |
| Select all across pages | Area tables select the visible page. Selecting every filtered result needs a "select all N matching" action that sends the filter instead of UIDs to the bulk endpoints. |
| Governance finding detail (PI-025) | Today the run page; a detail route would mirror `/application-security/findings/<id>`. |
| Application Security navigation | Already grouped (Overview, Applications, Scans, Vulnerabilities, Misconfigurations, Secrets, Licenses, Code, Components, SBOMs, Profiles, Settings, Triage) by the ASPM rebuild. |
| Earlier known items | SBOM page shows a temporary path as the artifact; triage save has no confirmation; scan-all dialog shows a generic error (from the ASPM verification). |
