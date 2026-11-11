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

No table, column or index changes. Existing rows are not rewritten.

### Runtime data writes introduced

* Mute rule created through `area-findings/mute`: one upstream `MuteRule` row; shared `Finding` rows of the latest scans get `muted=True` (the same write the upstream mute endpoint does).
* Application scans and mute rule changes set `AppSecFinding.suppressed` and `suppression` for UIDs in enabled rules, and clear them only on rows whose `suppression.source` is `mute_rule`. Scanner-side suppressions are never touched.
* No finding is deleted.

### Note on daily rules

Rules created with "Daily" before this release start sending once the beat task runs. django-celery-beat starts a new interval task's clock at its creation, so the first daily run is about 24 hours after deployment. Customers with daily rules will begin receiving the digests they configured.

## Rollback

| Scope | Action |
| --- | --- |
| UI only | Redeploy the previous Vercel deployment (Vercel dashboard, "Promote to production") |
| API and worker | Revert the merge commit on `main`; the deploy workflow redeploys the previous code |
| Daily alerts only | Disable the periodic task `cloudsneeker-evaluate-daily-alert-rules` (Django admin or `PeriodicTask.enabled = False`) |
| Migration | `manage.py migrate cloudsneeker_api 0025` removes the beat task; not required for a code rollback (the old code ignores it, the task name would then be unknown to the worker and logged) |
| Mute rules created through the new endpoint | They are ordinary upstream mute rules; disable or delete them on the Mutelist page |

## Backups

The VM takes a nightly `pg_dump` to Blob Storage. Take a manual dump before merging if a release also carries schema changes; this one does not.
