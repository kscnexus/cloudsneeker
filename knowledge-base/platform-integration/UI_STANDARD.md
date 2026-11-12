# UI Standard: Cloud Security Findings as the Reference

The Cloud Security Findings page (`/findings`) is the design and interaction reference for every list and finding page in Cloudsneeker. Other pages adopt its patterns. The Findings page itself is not changed unless it has a defect.

## The Reference Page

Source: `ui/app/(prowler)/findings/page.tsx`. It is built from upstream components, restyled app-wide by `ui/cloudsneeker/styles/surfaces.css` (CSS only).

| Part | Behaviour | Component |
| --- | --- | --- |
| Page shell | Title with icon, then the filters, then the table card | `ContentLayout` (`components/shadcn/content-layout`) |
| Filters | Searchable multi-selects with "Select All". Changes are staged until **Apply**. Applied filters show as removable chips. **Clear Filters** shows a count. Extra filters open under **More Filters** (date, region, service, and so on). | `BatchFiltersLayout`, `DataTableFilterCustom` (batch mode), `FilterSummaryStrip`, `ApplyFiltersButton`, `ClearFiltersButton`, `CustomDatePicker`, `useFilterBatch` |
| Filter state | In the URL: `filter[<field>]` with comma-separated values. Applying returns to page 1, and paging keeps the filters. | `useFilterBatch`, `useUrlFilters` |
| Table card | One bordered card. Its toolbar has the search on the left ("press Enter", `filter[search]`) and "N Total Entries" on the right. The table sits inside, with the pagination at the bottom behind a divider. | `DataTable` (`data-table-scroll-container`), `DataTableSearch` |
| Table | Tinted header, divided square rows, a hover edge, and a sticky row-actions column | shadcn `Table` + `surfaces.css` |
| Severity | Colour square and label (Critical, High, Medium, Low, Info) | `SeverityBadge` |
| Status | Badge per status | `StatusFindingBadge`, `StatusBadge` |
| Sorting | Column headers toggle `sort` (ascending, descending, off) | `DataTableColumnHeader` |
| Pagination | "Rows per page" (10, 20, 30, 50, 100; `pageSize`), "Page X of Y", first, previous, next and last. Server-side. | `DataTablePagination` |
| Selection | Row checkboxes and a page checkbox. A floating bar shows "N selected" with bulk actions (mute, Jira). | `FloatingSelectionActions` |
| Row actions | "…" menu per row | `DataTableRowActions`, `ActionDropdown` |
| Detail | A drawer opens from the row, with the finding, resource, remediation and history | `FindingDetailDrawer` |
| Loading | Filter and table skeletons, each streamed separately | `FindingsFiltersSkeleton`, `SkeletonTableFindings` |
| Errors | A red banner above the table with the API error | inline in `page.tsx` |
| Empty | "No results." row | `DataTable` |

## The Standard Kit

Cloudsneeker pages reuse the upstream components through a small kit in `ui/cloudsneeker/components/standard/`. Server pages pass plain data to it, so no function props cross the server boundary.

| Need | Use |
| --- | --- |
| Filter bar | `StandardFilters` with `StandardFilter[]` items (`key`, `label`, `options`, `single`, `wide`). It wraps `BatchFiltersLayout`, `DataTableFilterCustom`, the chips, Apply and Clear. |
| Table card, search, total | `StandardTableCard` (`searchPlaceholder`, `total`, `toolbarRight`, `footer`). It carries `data-table-scroll-container`, so `surfaces.css` draws it like the Findings table. |
| Pagination | `PageNav`: rows per page, "Page X of Y", first and previous, numbered pages, next and last. The numbered pages were added at the user's request. Everything else matches `DataTablePagination`. |
| Rows per page | `PageSizeSelect` (inside `PageNav` when `pageSize` is set) |
| Sort without sortable columns | `SortSelect` in the toolbar (`sort`) |
| Severity | `StandardSeverityBadge`, which renders the upstream `SeverityBadge` (and "unknown" as neutral) |
| URL helpers | `ui/cloudsneeker/lib/standard-list.ts` (`filter[...]`, `filter[search]`, `page`, `pageSize`, `sort`; legacy names stay readable) |
| Table markup | `TABLE_FRAME_CLASS`, `TABLE_CLASS`, `TABLE_HEAD_CLASS`, `TABLE_HEADER_CELL_CLASS`, `TABLE_BODY_CLASS` (`ui/cloudsneeker/lib/ui-classes.ts`) |

### Rules

- Put filters above the table card and the search inside the card's toolbar, as on Findings.
- Multi-value filters are searchable multi-selects with Select All. Yes/no filters are single selects ("Include muted findings", "Past deadline").
- Show only the filters that apply to the page.
- Applying, clearing or searching returns to page 1. Paging and rows per page keep every filter.
- A selection bar must say whether it covers this page or every match ("Select all 385 matching").
- Old links that use legacy names (`severity=`, `q=`, `account=` and so on) redirect to the current names, so the filter chips show what is applied.
- Keep module-specific detail: resource and configuration for cloud findings; CVE, package, file and fix for application findings; policy, run and raw resource for governance findings.

## Page Status

The statuses are:
- **Done:** the page uses the standard filters, card and pagination.
- **Standard filters:** the page uses the standard filter bar (`ListFilterBar`, built on `StandardFilters`) and `PageNav`, but its table is still the page's own card.
- **Shared look:** the page uses the shared table styles and `PageNav`, but its filters are its own.

| Module | Page | Route | Status |
| --- | --- | --- | --- |
| Cloud Security | Findings (reference) | `/findings` | Reference, unchanged |
| Cloud Security | Resources, Scans, Providers, Compliance, Attack Paths, Mutelist | upstream pages | Upstream components; already the reference look |
| Cloud Security | Alert history | `/alerts?tab=history` | Standard filters |
| Application Security | Findings, Vulnerabilities, Code, Misconfigurations, Secrets, Licenses | `/application-security/<segment>` | Done |
| Application Security | Scan history | `/application-security/scans` | Standard filters |
| Application Security | Applications, SBOMs | `/application-security/applications`, `/sboms` | Done |
| Application Security | Components (SCA) and SBOM detail components | `/application-security/components`, `/sboms/<id>` | Standard filters |
| Cloud Governance | Findings | `/governance/findings` | Done |
| Cloud Governance | Policies, Reports (dry runs) | `/governance?tab=policies`, `?tab=reports` | Standard filters |
| Cloud Governance | Library | `/governance/library` | Standard dropdowns (filtered in the browser) |
| All | Reports (recent reports) | `/reports` | Standard filters, with paging |
| All | Audit log | `/settings/audit-log` | Standard filters |

### Filters per Page

| Page | Filters |
| --- | --- |
| Governance findings | Severities, Statuses, Policies, Accounts, then under More Filters: Regions, Resource Types, Include muted. Search in the table toolbar; sort by Severity, Last seen, First seen or Rule. |
| Application Security findings (all six) | Severities, Priorities, States, Triage Statuses, then under More Filters: Applications, Targets, Asset Types, Time (first seen), Fix States (vulnerabilities only), Past deadline, Suppressed only. Search in the toolbar; sort by Priority, Severity, Newest, Last seen, Due date, Rule or Package. Rule and package scopes from links show as removable notes. |
| Governance policies | Accounts, Schedules, search |
| Governance dry runs | Accounts, Statuses, search |
| Application Security scan history | Target types, search |
| Alert history | Statuses, Modules, search |
| Applications | Criticalities, Environments, search in the toolbar |
| Components and SBOM components | Ecosystems, Relationships, Vulnerability states, Licenses, License statements, search, sort |
| SBOMs | Versions (newest per asset or all), Applications; asset scope from links |
| Governance library | Categories, Severities, search, starter pack and installed toggles |
| Recent reports | Report Types, Statuses, Triggers, rows per page |
| Audit log | Actions, Outcomes, From date, actor search, Export CSV |

Detail pages (finding, policy, run, application, SBOM) keep their own sections; see the detail page notes below.

## Detail Pages

The Cloud Security finding drawer has a header (severity, status, title and actions) and tabs: Overview, Remediation, Evidence, Other findings, Scans and Events. Detail pages follow it as far as their data allows, and keep their module-specific information:

| Page | Layout |
| --- | --- |
| Governance finding (`/governance/findings/<uid>`) | Header with severity, triage or muted status, and Mute. Tabs: Overview (resource, type, region, policy, rule, first and last seen, finding ID), Remediation (policy, the dry run that reported it, triage) and Evidence (the resource as the run reported it). |
| Application Security finding (`/application-security/findings/<id>`) | Header with priority, severity, state and triage, then cards for Technical details (CVE, package, versions, file and line), Remediation, References, History and Recent scans. Tabs would only rearrange this, so it keeps its cards. |
