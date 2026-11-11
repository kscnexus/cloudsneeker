# Deployment and Rollback

## Release Path

| Step | What runs | Where |
| --- | --- | --- |
| 1 | Pull request to `main` | "Cloudsneeker: Tests" runs SDK, API (with database), UI and MCP suites |
| 2 | Merge to `main` | Tests run again; Vercel builds the UI (`cloudsneeker.vercel.app`) |
| 3 | "Cloudsneeker: Deploy to Azure" after tests pass | Builds and scans images, starts `cloudsneeker-deploy.service` on the VM; migrations run on API start |
| 4 | Smoke checks | `/health/live`, then signed-in checks in [E2E Test Results](E2E_TEST_RESULTS.md) |

Nothing in this work changes CI, infrastructure, IAM or paid services.

## Database Changes

| Migration | Change | Data effect | Reversible |
| --- | --- | --- | --- |
| `cloudsneeker_api/0026_alert_daily_periodic_task` | Adds the beat task `cloudsneeker-evaluate-daily-alert-rules` (every 24 h) | None to customer data | Yes: reverse deletes the task |
| `cloudsneeker_api/0027_alert_events` (PR #7) | New table `cloudsneeker_alert_events` with its RLS policies (`SELECT`, `INSERT`, `UPDATE`, `DELETE`), a unique `(tenant_id, dedup_key)` constraint and two indexes | New, empty table; no existing table, column or row changes | Yes: reverse drops the table and its alert history |

Existing tables and rows are not changed.

### Runtime data writes introduced

* Mute rule created through `area-findings/mute`: one upstream `MuteRule` row; shared `Finding` rows of the latest scans get `muted=True` (the same write the upstream mute endpoint does).
* Application scans and mute rule changes set `AppSecFinding.suppressed` and `suppression` for UIDs in enabled rules, and clear them only on rows whose `suppression.source` is `mute_rule`. Scanner-side suppressions are never touched.
* No finding is deleted.
* Every alert rule firing writes one `AlertEvent` row before delivery (PR #7). Acknowledge, resolve, dismiss and reopen update that row.

### Note on daily rules

Rules created with "Daily" before this release start sending once the beat task runs. django-celery-beat starts a new interval task's clock at its creation, so the first daily run is about 24 hours after deployment. Customers with daily rules will begin receiving the digests they configured.

## Rollback

| Scope | Action |
| --- | --- |
| UI only | Redeploy the previous Vercel deployment (Vercel dashboard, "Promote to production") |
| API and worker | Revert the merge commit on `main`; the deploy workflow redeploys the previous code |
| Daily alerts only | Disable the periodic task `cloudsneeker-evaluate-daily-alert-rules` (Django admin or `PeriodicTask.enabled = False`) |
| Alert history (PR #7) | Revert the merge commit. The old code never reads the table, so it can stay; to remove it, run `manage.py migrate cloudsneeker_api 0026` before deploying the old code (this deletes the history) |
| Migrations | `manage.py migrate cloudsneeker_api 0025` removes the beat task and the alert history table; not required for a code rollback (old code ignores both; the beat task name would then be unknown to the worker and logged) |
| Mute rules created through the new endpoint | They are ordinary upstream mute rules; disable or delete them on the Mutelist page |

## Backups

The VM takes a nightly `pg_dump` to Blob Storage. Take a manual dump before merging a release that carries schema changes. Migration `0027` only adds a new table, so no existing data is at risk; a dump is still taken nightly.
