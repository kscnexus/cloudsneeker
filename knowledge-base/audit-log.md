# Audit Log

The user-action audit log (backlog item EB-007) records who did what in a tenant: sign-ins, changes to users, roles, memberships, invitations, providers, provider credentials, integrations, mute rules, scans, report share links and schedules, API keys, email delivery, Cloud Governance policies and Application Security targets. Tenant administrators read it at **Settings → Organization → Audit log** (`/settings/audit-log`) and export it as CSV.

## Where the code lives

| Piece | Location |
| --- | --- |
| Model | `api/src/backend/cloudsneeker_api/models.py` → `AuditEvent` (table `cloudsneeker_audit_events`, tenant RLS on all four statements) |
| Migration | `cloudsneeker_api/migrations/0012_audit_log.py` (table, indexes `(tenant_id, -inserted_at)` and `(tenant_id, action)`, RLS constraint, daily retention task) |
| Capture | `cloudsneeker_api/audit.py` → `AuditLogMiddleware`, `record_event`, `resolve_action`, `field_names` |
| Retention | `cloudsneeker_api/tasks.py` → `cloudsneeker-purge-audit-events` (Celery Beat, every day) |
| API | `cloudsneeker_api/views_audit.py`, `serializers_audit.py`, route `audit-events` in `cloudsneeker_api/urls.py` |
| UI page | `ui/app/(cloudsneeker)/settings/audit-log/page.tsx` |
| UI pieces | `ui/cloudsneeker/lib/audit-log.ts` (labels, filters, links), `components/audit-log-table.tsx`, `components/audit-log-filters.tsx`, `actions/audit-log.ts`, `types/audit.ts` |
| CSV proxy | `ui/app/api/cloudsneeker/audit-log/export/route.ts` |
| Sidebar | `ui/cloudsneeker/navigation.ts` adds "Audit log" as the last Organization child |
| Upstream hook | `config/django/base.py`: one `MIDDLEWARE` line marked `cloudsneeker-hook` (see [`upstream-hooks.md`](upstream-hooks.md)) |
| Tests | `cloudsneeker_api/tests/test_audit_log.py`; Vitest files next to each UI file |

## How events are captured

One middleware handles every request; no upstream view changes.

1. Only `POST`, `PUT`, `PATCH` and `DELETE` under `/api/v1/` are considered, plus `GET /api/v1/audit-events/export` (an export of the log is itself audited).
2. Before the view runs, a JSON body up to 1 MB is read so its **field names** can be recorded. Uploads and other content types are never read.
3. After the view answers, the resolved route gives the action:
   - router routes: `<namespace>.<verb>` from the router basename and view action (`create`, `update`, `delete`, or the custom `@action` name such as `connection`, `revoke`);
   - non-router views (relationship endpoints, Slack OAuth exchange) have an explicit map;
   - a few names are overridden where the generic one reads badly (`scan.create` → `scan.launch`, report share POST → `report.share_link.create`, …);
   - unknown routes are still recorded under a derived name, so new upstream endpoints are not silently missed. Read-only POSTs (token refresh, Attack Paths queries, alert preview) are skipped.
4. The tenant comes from the request token (`request.auth["tenant_id"]`). Unauthenticated requests other than sign-in (sign-up, public share links, alert confirm links) have no tenant and are not recorded.
5. The row is written in `rls_transaction(tenant_id)` on the default database. Any failure is logged and swallowed; auditing never changes a response.

Sign-in is handled by URL name:

| URL name | Recorded as |
| --- | --- |
| `token-obtain`, `token-saml`, `token-google`, `token-github` (success) | `auth.sign_in` in the tenant of the issued access token; `metadata.method` is `password`, `saml`, `google` or `github` |
| same, failure | `auth.sign_in_failed` in each tenant the email belongs to (only the requested tenant when the body names one, capped at 10). Unknown emails have no tenant and are not stored. |
| `token-switch` | `auth.switch_tenant` in the tenant switched to |

A successful tenant deletion is not recorded (the tenant and its log are being removed).

Operator console requests (`/api/v1/operator/*`) are skipped: they go to the cross-tenant `OperatorAuditEvent` table instead. A subscription change made by an operator is also written to the affected customer's log as `operator.subscription_update` (field names only, `metadata.operator: true`). Requests refused by the plan enforcement middleware (`subscription_inactive`, `feature_not_in_plan`, `plan_limit_reached`) never reach a view and are not recorded. See [Operator Console](operator-console.md).

## What a row holds

`actor_id` (plain UUID, no foreign key, so events outlive the user) and an `actor_email` snapshot; `action`; `target_type`, `target_id` (URL `pk` or the created object's id) and `target_label` (name, alias, email, uid… from the response); `outcome` (`success` below HTTP 400, otherwise `failure`, so permission denials are kept); `status_code`; `ip_address` (first valid `X-Forwarded-For` entry, else `REMOTE_ADDR`); `user_agent` (truncated to 512); `request_id` (the `Transaction-ID` from `django_guid`); `method`; `path`; `metadata`.

`metadata` never contains values. It holds attribute and relationship **names** (`fields`, `relationships`), `secret_fields_changed: true` when a name looks like a password, secret, token, key or credential (those names are not listed either), `view_action` for custom actions, `api_key_prefix` for API-key requests, and for sign-ins `method` / `reason`.

## API

All routes need the upstream `manage_account` permission. The log is append-only: there is no create, update or delete route (they return 405).

| Route | Notes |
| --- | --- |
| `GET /api/v1/audit-events` | JSON:API list, type `cloudsneeker-audit-events`, default sort `-inserted_at`, standard pagination. Filters: `action`, `action__startswith`, `action__in`, `actor` (UUID → `actor_id`, otherwise part of the email), `actor_email`, `actor_email__icontains`, `outcome`, `target_type`, `target_id`, `inserted_at__gte`, `inserted_at__lte` (ISO date or datetime; a date as upper bound covers the whole day). |
| `GET /api/v1/audit-events/{id}` | One event. |
| `GET /api/v1/audit-events/export?format=csv` | Same filters (as `filter[...]` or plain names), newest first, streamed, at most 100 000 rows. Cells that start with `=`, `+`, `-` or `@` are prefixed with `'` so spreadsheets do not evaluate them. |

## Retention

`cloudsneeker-purge-audit-events` runs daily (created by migration 0012) and deletes events older than `AUDIT_LOG_RETENTION_DAYS` (default 365; invalid or non-positive values fall back to 365). Tenants are listed on the admin database and purged one at a time inside their own RLS transaction.

## Adding a new audited action

Nothing is needed for a new router-based endpoint: it is recorded as `<basename>.<verb>`. To give it a nicer name, add the basename to `RESOURCE_NAMESPACES` (and, if needed, an `ACTION_OVERRIDES` entry) in `cloudsneeker_api/audit.py`, and a label in `NAMESPACE_LABEL` / `ACTION_LABEL` in `ui/cloudsneeker/lib/audit-log.ts`. Keep engine names out of UI labels. Code that is not an HTTP request (Celery tasks) can call `cloudsneeker_api.audit.record_event(tenant_id, action, ...)`.

## Known gaps

- Failed sign-ins for emails that match no user are only in the API logs (no tenant to store them in).
- Delete events carry the target id but no label (the object is gone before the response).
- Actions performed by Celery tasks or Django admin are not recorded unless they call `record_event`.
- SAML ACS and other allauth form posts outside `/api/v1/` are not recorded; the SAML token exchange (`token-saml`) is.
