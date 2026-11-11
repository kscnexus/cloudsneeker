# Module Integration Matrix

State on 2026-11-11 after the changes in [Implementation Changelog](IMPLEMENTATION_CHANGELOG.md). Issue IDs refer to [Platform Integration Audit](PLATFORM_INTEGRATION_AUDIT.md).

Legend: **Integrated** works end to end through the shared path. **Partial** works with a stated gap. **Module-specific** differs on purpose. **Gap** is missing.

| Shared capability | Cloud Security | Application Security | Cloud Governance |
| --- | --- | --- | --- |
| Findings list | Integrated: upstream `/findings` | Integrated: `/application-security/findings` and per-category workspaces | Integrated: `/governance/findings` (latest run per policy) |
| Finding detail | Integrated: findings drawer | Integrated: `/application-security/findings/<id>` | Partial: policy run page lists the resource; no page per finding (PI-025) |
| Alerts | Integrated (PI-001, PI-005) | Integrated: engine scans now evaluate rules (PI-002) | Integrated for rules that name the governance area (PI-003) |
| Alert links | Integrated: scan's failing findings | Integrated: the application scan run | Integrated: the policy run |
| Alert lifecycle (acknowledge, resolve) | Yes (PI-023) | Yes | Yes |
| Mutelist | Integrated: upstream | Integrated: rescans, every target, posture rows (PI-009 to PI-011) | Integrated: `area-findings/mute`, read-time hiding (PI-012) |
| Mute from the module UI | Integrated: upstream | Integrated: bulk bar and finding detail (PI-013) | Integrated: bulk bar |
| Triage status and notes | Integrated | Integrated | Integrated |
| Risk acceptance with expiry | Integrated | Integrated | Integrated |
| Reports | Integrated: posture, compliance, executive | Partial: SCA, SAST, container, IaC, secrets; no license, SBOM or remediation report (PI-022) | Partial: governance dry-run report; muted always 0 |
| Dashboard | Integrated: `/cloud-security` | Integrated: `/application-security` | Integrated: `/governance` |
| Risk overview | Integrated: executive report run | Integrated (executive report) | Integrated (executive report) |
| Search and filters | Integrated: upstream filter bar | Integrated: finding workspaces; targets now searchable and paged (PI-019) | Integrated: findings; policies and runs now searchable and paged (PI-018) |
| Scheduled operations | Integrated: scan schedules | Integrated: target schedules | Integrated: policy schedules |
| Scan profiles | Integrated: scan configurations | Integrated: application scan profiles | Module-specific: a policy is its own profile |
| RBAC | Integrated: provider groups | Integrated: provider visibility | Integrated after PI-017 |
| Seeker AI | Integrated: upstream tools | Integrated (PI-020) | Integrated (PI-020) |
| Audit logging | Integrated: middleware records every write | Integrated | Integrated |
| Compliance | Integrated: Single Scan by provider and account (PI-014, PI-015) | Module-specific: CWE and OWASP categories on findings, no framework | Module-specific: policies map to cloud checks |

## Legitimate Differences

* Attack paths are cloud-only: code and policy findings have no resource graph.
* Governance severity comes from the policy document (`metadata.severity`, default medium).
* Governance findings are evaluated in memory from the latest run (at most the stored resources per run), so very large policies are summarized, not paged at the database.
* Application Security keeps its own lifecycle (`new`, `open`, `fixed`, `reopened`); cloud findings use scan deltas.

## Alert History (PI-023)

`AlertEvent` (`cloudsneeker_api` migration `0027`, tenant RLS) stores one row per rule firing: rule (kept as `rule_name` when the rule is deleted), trigger, scan or policy run, areas, counts per area and severity, links, delivery flag, status (`open`, `acknowledged`, `resolved`, `dismissed`), who changed it and when, and a note.

* Written by `alert_dispatch.evaluate_and_notify` before delivery. `dedup_key` is per rule per scan, per policy run, or per day for daily rules, so a retried evaluation finds the event and does not notify twice. A history write failure is logged and delivery still runs.
* API: `GET /alerts/events` (filters `status`, `status__in`, `area`, `severity`, `rule`, `trigger`, `inserted_at__gte/lte`, `search`) and `PATCH /alerts/events/{id}` (status and note only, `manage_scans`).
* UI: `/alerts?tab=history` with Status and Module filters, search, paging, and Acknowledge, Resolve, Dismiss and Reopen.
* Not built: automatic resolution when a later scan no longer matches, and a history entry per status change (only the latest change is kept).
