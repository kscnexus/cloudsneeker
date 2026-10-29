# Product Redesign and Reporting Plan

Started 2026-10-29. Goal: Cloudsneeker reads as one security platform (cloud
security, application security, governance, compliance, reporting), not
Prowler plus bolted-on tools. Functionality stays; this work is product
structure, UI/UX, a SAST engine, and reporting.

Decisions (user, 2026-10-29): start now on `main`, deploy in phases; add a SAST
engine; ship every report format (branded PDF, scheduled email, Excel/CSV,
in-app shareable report); refine the current neon brand (no new look).

## Phase 1: One product structure

Sidebar sections and product names. Engine names (Trivy, Cloud Custodian,
Prowler) never appear in the UI.

| Section | Items | Backed by |
| --- | --- | --- |
| Overview | Security posture dashboard | upstream overview |
| Cloud Security | Findings, Resources, Attack Paths, Scans | upstream |
| Application Security | Overview, Dependencies (SCA), Code (SAST), Containers, Infrastructure as Code, Secrets | Trivy Hub targets by mode; SAST engine (Phase 3) |
| Cloud Governance | Policies, Dry-run reports | Custodian |
| Compliance | Frameworks, Multiple Scans | upstream + scan comparison |
| Reports | Report catalog (Phase 4) | new |
| Seeker AI | Chat | upstream lighthouse |
| Settings | Sources (providers), Integrations, Alerts, Mutelist, Scan profiles, Organization | upstream |

Existing routes (`/trivy`, `/custodian`) keep working; new product routes
(`/application-security`, `/governance`) are added as the primary entries.

Shipped (UI, pending deploy):

- Sidebar (`ui/cloudsneeker/navigation.ts`): Overview and Seeker AI; CLOUD
  SECURITY (Findings, Resources, Attack Paths, Compliance); APPLICATION
  SECURITY; GOVERNANCE; OPERATIONS (Scans, Alerts, Scan profiles, CLI Import);
  SETTINGS (Configuration: Sources & Providers, Mutelist, Integrations, Seeker
  AI settings; Organization: Profile, Users, Invitations, Roles).
- Routes (`ui/cloudsneeker/routes.ts`): `/application-security`, `/new`,
  `/<targetId>`, `/<targetId>/edit`, `/<targetId>/runs/<runId>`;
  `/governance`, `/new`, `/<policyId>`, `/<policyId>/edit`,
  `/<policyId>/runs/<runId>`. `/trivy/*` and `/custodian/*` answer with a
  permanent redirect to the same sub-path and query.
- Product names come from `BRAND.appSecurityName` / `BRAND.governanceName`;
  page copy, mode labels, empty states, errors and export file names no longer
  name an engine. API endpoints (`/api/v1/trivy-*`, `/api/v1/custodian-*`) and
  internal identifiers are unchanged.
- Not yet: the Application Security sub-pages by mode (Dependencies, Code,
  Containers, IaC, Secrets), Reports, and API-side copy (error messages,
  template text) that the API returns verbatim.

## Phase 2: UX refresh (neon brand, refined)

- Overview: one risk view across cloud, application and compliance (score, top
  risks, trend, coverage of sources).
- Consistent page header, empty states, cards, tables and spacing on every
  Cloudsneeker page; Application Security and Governance hubs get dashboards.

Status: UI done (pending deploy).

- Shared components (`ui/cloudsneeker/components/`): `PageHeader`
  (description, record facts, actions), `StatTile` (KPI tile, optional link,
  tone accent, selected state), `SectionCard` (labelled region with title,
  description, actions), `EmptyState`, `SeverityBreakdown` (proportion bar +
  per-severity drill-down), `RunStatusBadge`. Focus ring and list classes in
  `ui/cloudsneeker/lib/ui-classes.ts`. Colors come from the existing theme
  tokens only, so light and dark themes both apply.
- Overview: `RiskOverview` (one hook in the upstream Overview page, recorded
  in `upstream-hooks.md`) reads the newest completed executive report run
  (`listReportRuns` + `getReportRunData`): score ring and grade, open issues,
  severity totals linked to Findings, one tile per area (Cloud posture,
  Application Security, Compliance, Cloud Governance) linked to its hub, top
  risks linked to their failed findings, and an open-issues trend. Without a
  report it shows an empty state with "Build risk view" (starts an executive
  report run); while a newer run is generating it says so. Helpers in
  `ui/cloudsneeker/lib/risk-overview.ts`.
- Application Security hub: KPI tiles (targets, scans, open findings, last
  scan), open findings by severity across each target's latest completed scan
  (`/findings` counts filtered by `scan__in`), coverage by area cards
  (Dependencies, Code (SAST), Containers, Infrastructure as Code, Secrets,
  SBOM, Kubernetes) that filter the target list via `?category=`, then targets
  and recent scans. Helpers in `ui/cloudsneeker/lib/app-security-dashboard.ts`.
- Governance hub dashboard, policy detail, target and scan detail pages, and
  Reports pages use the shared components.
- Alerts and Scan profiles (upstream pages): one marked hook each renders KPI
  tiles above the upstream list (`AlertsSummary`: rules, active, paused,
  destinations; `ScanProfilesSummary`: profiles, providers with a profile,
  providers on defaults, last edited). Counts in `ui/cloudsneeker/lib/ops-summary.ts`.
  The upstream tables, modals and the alert rule form stay as they are.
- CLI Import (`/scans?import=1`): one hook in the upstream Import findings
  dialog renders `CliImportSteps` (CLI command, pick the `.ocsf.json`, start);
  `theme.css` turns the dialog's status lines into callouts.
- Create/edit forms (Application Security target, Governance policy, report
  schedule) share `ui/cloudsneeker/components/form-layout.tsx` (`FormField`,
  `FormChoiceGroup`, `FormAlert`, `FormActions`) and the form classes in
  `ui-classes.ts`: one column, `SectionCard` per section, help text under the
  control, field errors with `role="alert"`, save error above a submit row that
  stacks full width on phones. New/edit pages get a `PageHeader` description.
  Code archive inputs accept `.zip,.tar,.tar.gz,.tgz,.tar.bz2,.tar.xz` and
  reject other files (7-Zip, RAR) before upload.
- Phone navbar: `theme.css` keeps the header inside a 375px viewport (title
  truncates; the duplicate Profile text link and the updates feed are hidden
  below `sm`). Recorded under CSS-only overrides in `upstream-hooks.md`.

## Phase 3: SAST engine

- Engine: **OpenGrep** v1.30.2 (LGPL-2.1 fork of Semgrep OSS), the
  self-contained release binary at `/opt/opengrep/opengrep` in the API/worker
  image (`cloudsneeker/deploy/docker/api.Dockerfile`, sha256-pinned).
  `OPENGREP_BIN` / `OPENGREP_RULES_DIR` point at it.
- Rules: **GitLab sast-rules** `v2.10.1`, vendored at build time into
  `/opt/opengrep/rules`, keeping only the top-level language folders `csharp`,
  `go`, `java`, `javascript` (also TypeScript), `python`, `scala`. Those rules
  are MIT (c) GitLab, plus Apache-2.0 gosec ports in `go/`. Dropped from that
  repository: `rules/lgpl-cc` (Commons Clause), `rules/lgpl`, `rules/gitlab`
  (GitLab EE license), `c/` (GPL-2.0 flawfinder ports).
- Never ship: Semgrep registry rules (`p/...`, `semgrep/semgrep-rules`), whose
  Semgrep Rules License forbids use in a competing hosted product; and
  `opengrep/opengrep-rules`, which is LGPL-2.1 **plus the Commons Clause** (no
  selling a product or hosting service whose value derives from the rules).
  Adding a rule pack needs a license check of every file first.
- Mode `sast` ("Static analysis (SAST)") on Application Security targets,
  migration `cloudsneeker_api/0010_trivytarget_sast_mode`. Linked provider must
  be an IaC (repository) provider. Config: `repository_url` (must equal the
  provider's repository, as in repo mode) or `archive_b64` (code archive);
  `rulesets` (`auto` default = detect languages, `all`, or names from
  `SAST_RULESETS`); `exclude` globs (max 50).
- Run: dulwich shallow clone with the provider token
  (`cloudsneeker.git_auth.authenticated_clone_url`), `.git` removed, then
  `opengrep scan --json --disable-version-check --config=<pack>... --exclude=...
  --timeout=<OPENGREP_RULE_TIMEOUT_SECONDS> .` in the checkout. Clone and scan
  share the `TRIVY_HUB_TIMEOUT_SECONDS` budget. Tokens are redacted from errors
  and the report. OpenGrep has no `--metrics` flag; it only reports metrics
  when the Semgrep registry is used, which never happens here.
- Import: `trivy_import.opengrep_results_to_finding_rows` into the shared
  Scan / Finding rows (`scanner_args {"source": "trivy_hub", "mode": "sast"}`).
  Severity: `metadata.security-severity` when present, else ERROR -> high,
  WARNING -> medium, INFO -> low; high with impact and confidence HIGH ->
  critical. Resource = source file; finding UID = rule + file + line range,
  bounded to 300 characters with a digest suffix. CWE / OWASP go to
  `Categories`, `fix` to the remediation.
- Code: `cloudsneeker_api/services/sast.py`, tests in
  `cloudsneeker_api/tests/test_sast.py`. No upstream hooks.
- UI (done, pending deploy): mode "Static analysis (SAST)" in
  `ui/cloudsneeker/lib/trivy-modes.ts`. The target form
  (`components/trivy-target-form.tsx`, schema `lib/trivy-form-schema.ts`)
  asks for a Git repository URL or a code archive upload, rule packs (`auto`
  by default, `all`, or languages; `auto` and `all` stand alone) and exclude
  globs (one per line, at most 50, 200 characters each). It sends
  `config.repository_url` or `config.archive_b64`, `config.rulesets` and
  `config.exclude`, and no `scanners`. Editing an archive target needs the
  archive uploaded again because the API never returns it.

## Phase 4: Reporting

- Catalog: Executive summary (management), Cloud posture, Compliance (per
  framework), Software composition (SCA), Static application security (SAST),
  Container images, Infrastructure as Code, Secrets, Cloud governance.
- One data-assembly service per report in `cloudsneeker_api`, rendered to:
  branded PDF (extend `tasks/jobs/reports` style), Excel/CSV, an in-app
  report page with an expiring share link, and scheduled email (existing
  per-tenant SMTP, Celery Beat).

Backend (done, `api/src/backend/cloudsneeker_api/reports/`):

- `catalog.py`: the nine report types, parameter validation (`provider_ids`,
  `date_from`, `date_to`, `severity_floor`, `trend_points`; compliance adds
  `compliance_id` and an optional `scan_id`), formats, and the
  `cloudsneeker-<type>-<date>.<ext>` file name.
- `data/`: one assembler per type returning `ReportData` (`schema.py`):
  score and grade, KPIs, severity / status totals, trend, top risks with
  business impact and fix, per-source breakdown, compliance posture,
  remediation priorities, bounded detail tables (`REPORT_MAX_DETAIL_ROWS`,
  default 5000). Cloud data is the latest Prowler scan per cloud provider;
  application security data is the latest scan per provider and Trivy Hub
  mode (`scanner_args.source == "trivy_hub"`); governance is the latest
  Custodian dry-run per policy. SAST reads mode `sast` and shows an empty
  state until that mode has scans.
- `render/`: branded PDF (cover, contents, summary, charts, risks, sources,
  compliance, actions, detail tables, methodology appendix) built on the
  `tasks/jobs/reports` styles, XLSX (summary + detail sheets, frozen header,
  autofilter), CSV (main detail table), JSON (in-app payload).
- Runs write artifacts under
  `$DJANGO_TMP_OUTPUT_DIRECTORY/cloudsneeker-reports/<tenant>/<run>/` (the
  EFS volume shared by API and workers). Celery: `cloudsneeker-generate-report`
  and the beat task `cloudsneeker-scheduled-report`, which generates inline
  and emails the PDF through the tenant SMTP config (attachment up to
  `REPORT_EMAIL_MAX_ATTACHMENT_MB`, default 10; larger reports send a 7-day
  share link).
- Tables (migration `0011_reports`): `cloudsneeker_report_runs`,
  `cloudsneeker_report_schedules`, `cloudsneeker_report_share_links` (only
  the SHA-256 of the token is stored).

Endpoints (all under `/api/v1/`):

| Method and path | Purpose | Permission |
| --- | --- | --- |
| `GET report-types`, `GET report-types/{id}` | Catalog | Signed in |
| `POST report-runs` | Enqueue a report (`report_type`, `params`, `formats`) | Signed in; providers pinned to the role's visibility |
| `GET report-runs`, `GET report-runs/{id}`, `DELETE report-runs/{id}` | History | Limited roles see their own runs and runs over visible providers |
| `GET report-runs/{id}/download?format=pdf\|xlsx\|csv\|json` | Artifact download | Same as above |
| `GET report-runs/{id}/data` | JSON payload for the in-app report page | Same as above |
| `GET, POST report-runs/{id}/share-links` | List / create a share link (raw token returned once) | Create needs `manage_scans` |
| `GET report-share-links`, `POST report-share-links/{id}/revoke` | Manage share links | `manage_scans` |
| `GET, POST, PATCH, DELETE report-schedules` | Scheduled email reports (cron + timezone, recipients) | `manage_scans` |
| `GET shared-reports/{token}` | Public report JSON; expiry and revocation enforced, per-IP throttle `REPORT_SHARE_THROTTLE` (default 60/min) | None |

UI (done, pending deploy):

- Sidebar section REPORTS -> Reports (`/reports`), between Governance and
  Operations (`ui/cloudsneeker/navigation.ts`, feature flag `reports`).
- `/reports` (`ui/app/(cloudsneeker)/reports/page.tsx`), tabs Reports |
  Schedules | Share links (`?tab=schedules`, `?tab=share-links`):
  - Catalog cards with product copy (`ui/cloudsneeker/lib/report-catalog.ts`).
    Generate opens a dialog with sources, date range, minimum severity,
    framework (compliance report; ids come from the compliance overviews of
    the latest completed scan per provider, up to five) and formats (PDF,
    Excel, CSV; JSON is always produced for the in-app page).
  - Recent reports: status badge, refresh every 5 s while a run is queued or
    generating (`components/scans/auto-refresh`), one download button per
    file, View, Share (expiry 24 h, 3 d, 7 d or 30 d; the URL is shown once
    with a copy button), delete.
  - Schedules: list, create, edit, delete, enable toggle. Cadence presets
    daily, weekly, monthly or custom cron, timezone, recipients, formats
    (`ui/cloudsneeker/lib/report-schedule.ts`).
  - Share links: state, expiry, views, revoke.
- `/reports/<runId>`: in-app report (`ui/cloudsneeker/components/report-view.tsx`)
  with grade ring, KPI tiles, severity bars, trend line, top risks with
  business impact and fix, per-source breakdown, compliance posture bars,
  next actions, and detail tables paged at 25 rows. Print styles and a Print
  button.
- Downloads use `GET /api/cloudsneeker/reports/<runId>/download?format=`
  (`ui/app/api/cloudsneeker/reports/[runId]/download/route.ts`). It forwards
  the session token and streams the API file with its content type and
  branded file name.
- Public `/shared-reports/<token>` (`ui/app/(cloudsneeker-public)/`; the root
  document is re-exported from the `(auth)` layout, no sidebar). It reads
  `shared-reports/<token>` on the server without session headers and renders
  the same report view under the brand header, read only and `noindex`.
  Expired, revoked, unknown and unavailable tokens each get their own state.
  `proxy.ts` lists the path as public (hook).
- Share and schedule controls show only with `manage_scans`; the API enforces
  the same rule.

Pending: deploy and verify on ECS.

## Status

| Phase | State |
| --- | --- |
| 1 | Done (pending deploy) |
| 2 | Not started |
| 3 | Backend done; UI done (pending deploy) |
| 4 | Backend done; UI done (pending deploy) |
