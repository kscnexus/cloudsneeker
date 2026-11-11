# RBAC and Tenant Isolation Audit

## Model

* Tenant isolation: every Cloudsneeker table is row-level security protected (`RowLevelSecurityConstraint`) and every view runs inside `rls_transaction(tenant_id)` (`BaseRLSViewSet`). The tenant comes from the JWT, never from the request body.
* Provider visibility: a role with `unlimited_visibility` sees every provider; any other role sees the providers in its provider groups (`reports/access.visible_provider_ids`).
* Permissions: writes that change scans, findings, rules or policies need `manage_scans`; reports, users, integrations and billing have their own upstream permissions.
* The frontend hides controls by permission, but every rule is enforced by the API.

## Endpoint Families

| Family | Read | Write | Provider visibility | Notes |
| --- | --- | --- | --- | --- |
| Upstream findings, scans, providers, mute rules | Upstream | `manage_scans` (mute rules) | Yes | Unchanged |
| `area-findings` | Plan feature of the area | `area-findings/mute`: `manage_scans` | Yes; mute checks every UID is visible to the role | New mute action |
| `finding-triages` | Plan + visibility | `manage_scans` | Yes | Unchanged |
| `appsec-*`, `trivy-*` | `application_security` plan + visibility | `manage_scans` | Yes | Unchanged |
| `custodian-policies`, `custodian-runs` | **Was** `manage_scans`, no visibility filter. **Now** visibility only | `manage_scans` | **Now yes** | PI-017 |
| `alert-rules` | Upstream contract | Upstream contract | Rules are tenant-wide; matched findings are the tenant's | Notifications go to confirmed recipients only |
| Reports | `reports` permissions | | `scope_params_to_role` pins providers | Unchanged |
| Seeker AI tools | User token | None (read-only) | Inherited from the API | New tools |

## Findings

| ID | Finding | Fix | Test |
| --- | --- | --- | --- |
| PI-017 | Governance reads needed `manage_scans` and ignored provider groups | Reads filtered by `visible_provider_ids`; writes keep `manage_scans` | `test_governance_access.py`: limited role reads nothing it cannot see and cannot create |
| RB-002 | Muting governance findings had no permission path | `area-findings/mute` needs `manage_scans` and skips UIDs the role cannot see | `test_area_mute.py` |
| RB-003 | Alert evaluation runs as the tenant, not as a user | By design: rules are tenant-wide; the notification lists counts and links, and following a link enforces the reader's own visibility | — |

## Cross-Tenant Checks

Covered by existing tests (`test_area_findings.py::test_limited_role_sees_nothing_without_providers`, the upstream RLS suites) and by the new tests above. A two-tenant run on the deployed site needs a second tenant and user, which the deployment does not have; see [E2E Test Results](E2E_TEST_RESULTS.md).
