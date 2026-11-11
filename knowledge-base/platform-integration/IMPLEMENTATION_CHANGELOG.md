# Implementation Changelog

Branch `claude/cloudsneeker-integration-consistency-0376b7`, started from `main` at `ab35807eb` on 2026-11-11.

| Commit | Area | Issues | Summary |
| --- | --- | --- | --- |
| `feat(alerts): route alerts and mute rules by product area` | API | PI-001 to PI-012 | Area field in alert conditions; alert evaluation for application scans and governance runs; daily beat task (migration 0026); FAIL and unmuted only; per-module notification links; area-aware preview and seeding. Application scans apply the mutelist; rule changes reach every target and posture rows; `POST area-findings/mute`; governance read path honours mutes |
| `feat(ui): module-aware alerts, cross-module muting, provider-first compliance` | UI | PI-006, PI-013 to PI-015, PI-026 | Modules column and selector, New alert, Create alert links; Mute button; Single Scan provider, account, scan steps; sidebar opens Single Scan |
| `fix(governance): read access by provider visibility; paged, searchable lists` | API, UI | PI-017 to PI-019 | Governance RBAC fix and filters; list filter bar and pager; target list search, type filter and pagination |
| `feat(seeker-ai): read Application Security and Governance data` | MCP, UI | PI-020, PI-021 | Five read-only tools, allowlist, prompt section |
| `docs(platform): integration audit, matrix and reports` | API, docs | RC-001 | Governance report counts muted resources; executive governance open issues exclude them; the nine audit documents; hook list |

## New Files

| File | Purpose |
| --- | --- |
| `api/.../services/alert_evaluation.py` | Areas of a rule, governance evaluator, links, notification body, seeding and preview |
| `api/.../services/alert_dispatch.py` | Rule selection per trigger, delivery, after-commit enqueue |
| `api/.../services/area_mute.py` | Shared mutelist for application and governance findings |
| `api/.../migrations/0026_alert_daily_periodic_task.py` | Daily alert beat task |
| `api/.../tests/test_alert_areas.py`, `test_area_mute.py`, `test_governance_access.py` | Tests |
| `ui/cloudsneeker/lib/alert-areas.ts`, `components/alert-area-field.tsx` | Alert modules |
| `ui/cloudsneeker/components/mute-findings-button.tsx` | Mute action |
| `ui/cloudsneeker/compliance/single-scan-scope.ts`, `compliance-scope-filters.tsx` | Provider-first Single Scan |
| `ui/cloudsneeker/lib/list-filters.ts`, `components/list-filter-bar.tsx` | Shared list filters and pager |
| `mcp_server/prowler_mcp_server/cloudsneeker/tools/area_findings.py` | Seeker AI tools |
