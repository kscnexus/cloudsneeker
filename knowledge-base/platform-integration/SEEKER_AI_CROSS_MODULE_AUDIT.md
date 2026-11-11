# Seeker AI Cross-Module Audit

## Before This Work

Seeker AI reaches data only through MCP tools that the UI allowlists (`ui/lib/lighthouse-v1/allowed-tools.ts`). Every allowlisted tool read cloud posture data: findings, finding groups, providers, scans, mutelist, compliance, resources and attack paths. No tool read area findings, application security data or governance policies. Application Security rows that live in the shared `Finding` table could appear in a cloud finding search, labelled as cloud; governance was unreachable.

Answer: Seeker AI was effectively limited to Cloud Security.

## Now

| Module | Tools | Source |
| --- | --- | --- |
| Cloud Security | Upstream finding, resource, scan, compliance, attack path tools | Upstream API |
| Application Security | `search_area_findings` (area `application_security`), `get_application_security_overview`, `get_application_security_finding` | `GET /area-findings`, `GET /appsec/overview`, `GET /appsec-findings/<id>` |
| Cloud Governance | `list_governance_policies`, `search_area_findings` (area `governance`) | `GET /custodian-policies`, `GET /area-findings` |
| All | `get_platform_posture_summary`: open findings per module and severity; a module that fails or is outside the plan is reported unavailable, not zero | `GET /area-findings` |

Code: `mcp_server/prowler_mcp_server/cloudsneeker/tools/area_findings.py`, loaded by a hook in `prowler_app/server.py`, allowlisted through `CLOUDSNEEKER_AREA_TOOLS` in `ui/cloudsneeker/lighthouse-tools.ts`. Prompt rules: `MODULES_SECTION` in `ui/cloudsneeker/lighthouse-prompt.ts`.

## Security

* Every tool calls the public API with the signed-in user's token, so tenant row-level security, provider-group visibility (`visible_provider_ids`) and the plan gate apply exactly as on the pages.
* All five tools are read-only. No write tool was added.
* Results carry a `module` and a `source` page so answers can cite them. The prompt requires that only tool data is reported as fact and that advice is labelled as a recommendation.

## Page Context

The chat already sends the current path for every page (fallback page definition). The prompt now tells the agent that `/application-security/findings/<id>` means "this finding" and to fetch it before answering. Upstream page definitions with tailored suggestions still exist only for upstream pages.

## Test Questions

| Question | Tools expected |
| --- | --- |
| Show me all critical security findings across the platform | `get_platform_posture_summary`, then `search_area_findings` per module with severity critical |
| Which applications have the highest vulnerability exposure | `get_application_security_overview` |
| Which repositories contain critical CVEs | `search_area_findings` area application_security, severity critical |
| What are my most significant governance violations | `search_area_findings` area governance, sort severity |
| Compare application security risk with cloud security risk | `get_platform_posture_summary` |
| Which findings are overdue | `search_area_findings` area application_security, `overdue_only` |
| How do I fix this (on an application finding page) | `get_application_security_finding` with the id from the path |

Status: tool behaviour is covered by `mcp_server/tests/cloudsneeker/test_area_tools.py` (runs in CI). Asking these questions live needs a working model key on the tenant; see [E2E Test Results](E2E_TEST_RESULTS.md).
