# Finding Triage

Finding triage (backlog item EB-010) records a workflow status and a note thread for each finding. The data lives in Cloudsneeker tables. The upstream findings API, its filters, and its migrations are unchanged.

## Data Model

Upstream `Finding` rows belong to one scan. `Finding.uid` stays the same across rescans, so triage is keyed by `(tenant, finding_uid)`. A status set today still applies after the next scan.

| Table | Model | Holds |
| --- | --- | --- |
| `cloudsneeker_finding_triages` | `FindingTriage` | `finding_uid` (unique per tenant), `status`, `status_changed_at`, `source`, `check_id`, `provider`, `assignee`, `updated_by`, timestamps |
| `cloudsneeker_finding_triage_notes` | `FindingTriageNote` | `triage`, `author`, `body` (plain text, at most 4000 characters), `status` the triage moved to with this note, timestamps |

Both tables use tenant row-level security (`RowLevelSecurityConstraint`, migration `cloudsneeker_api/migrations/0013_finding_triage.py`). `check_id` and `provider` are copied from the latest finding with the UID on every write. Provider visibility and the `check_id` and `provider` filters read them without joining the partitioned findings table.

### Statuses

The status values are the ones the inherited findings UI already renders (`ui/types/findings-triage.ts`):

| Value | Meaning |
| --- | --- |
| `open` | Not triaged yet, or triaged back to open |
| `under_review` | Someone is investigating |
| `remediating` | A fix is in progress |
| `resolved` | Fixed. The UI asks for evidence (a note) and then locks the status |
| `risk_accepted` | Accepted risk. EB-019 adds expiry and approver |
| `false_positive` | Not a real issue |
| `reopened` | Failing again after it was resolved |

The API returns `status` as the effective status. A `resolved` triage reads as `reopened` when the finding failed, unmuted, in a scan newer than `status_changed_at`. `stored_status` is the value in the table. The read path never rewrites the stored status.

`source` is `manual`, `bulk`, `integration`, or `automation`. `integration` and `automation` are reserved for Jira or ServiceNow sync (EB-031, EB-042) and for rescan automation.

### Extension Points

* EB-019 (risk acceptance): add nullable `accepted_until`, `approver`, and `reason` columns to `FindingTriage`, and an expiry task that sets `reopened` with `source=automation`.
* EB-020 (ownership): `assignee` already exists. Add assignment rules in a new table and a "My findings" view filtered with `filter[assignee]`.
* EB-021 (SLA): SLA dates come from `Finding.first_seen_at` and severity. Count `false_positive` and `risk_accepted` triage as excluded from overdue counts.

## API

All routes are under `/api/v1/` (`cloudsneeker_api/urls.py`, views in `cloudsneeker_api/views_triage.py`, logic in `cloudsneeker_api/services/finding_triage.py`).

| Method and path | Purpose |
| --- | --- |
| `GET finding-triages` | List triage. Filters: `status`, `status__in`, `assignee`, `check_id`, `check_id__in`, `provider`, `provider__in`, `finding_uid`, `finding_uid__in`. Sort: `updated_at`, `inserted_at`, `status_changed_at`, `status`. Paginated |
| `GET` / `PATCH finding-triages/{id}` | Read or change one triage. `{id}` may also be a UID without `/` or `.` |
| `POST finding-triages/bulk` | `finding_uids` (at most 500), `status`, optional `note`. Returns `created`, `updated`, `unchanged`, `skipped_uids` (UIDs with no visible finding) |
| `GET finding-triages/lookup` | `filter[finding_id__in]` and/or `filter[finding_uid__in]` (at most 200). One entry per triaged finding row, used to show triage in the findings table |
| `GET` / `POST finding-triages/{id}/notes` | Note thread, newest first |
| `PATCH` / `DELETE finding-triages/{id}/notes/{note_id}` | Edit or delete a note (author only) |
| `GET` / `PATCH findings/{finding_uid}/triage` | The paths the inherited UI calls. `GET` on an untriaged visible finding returns `status: open` with `id: null`. `PATCH` creates the row (upsert, `201`) or updates it (`200`) |
| `GET` / `POST findings/{finding_uid}/triage/notes`, `PATCH` / `DELETE .../notes/{note_id}` | Same note thread by UID. The first `POST` creates the triage |

`PATCH` accepts `status`, `note`, and `assignee_id`. The assignee must be a member of the tenant. A note sent with a status change records that status on the note.

The UID routes use Django's `path` converter, so UIDs that contain `/` work when the client URL-encodes them. Upstream `findings/{pk}` routes never match these paths, because their `pk` pattern excludes `/` and `.`.

Request bodies are parsed with `LenientJSONAPIParser`, so the unprefixed types the UI sends (`finding-triages`, `finding-triage-notes`) are accepted. Responses use `cloudsneeker-finding-triages` and `cloudsneeker-finding-triage-notes`.

### Permissions

* Reading follows finding visibility. A role with `unlimited_visibility` sees every triage of the tenant. Any other role sees triage whose provider is in its provider groups (`reports/access.py`, `visible_provider_ids`). UID routes return `404` for findings the role cannot see.
* Writing (`PATCH`, `POST`, `DELETE`) requires `manage_scans`.
* Only the author can edit or delete a note.

## UI

The inherited findings UI already has a triage column, a status selector, a detail control, and a note modal. Upstream only enables them in the cloud edition. Cloudsneeker turns them on through the following hooks (rows in [Upstream Hooks](upstream-hooks.md)):

* `actions/findings/findings-triage.options.ts` makes triage editable when `CLOUDSNEEKER_FEATURES.findingTriage` is on.
* Five server-action call sites wrap their response in `withCloudsneekerTriage` (`ui/cloudsneeker/lib/finding-triage-server.ts`). It looks up `finding-triages/lookup` for rows that carry no triage fields, then merges `triage_status`, `triage_id`, and note counts into each row. If the lookup fails, the findings still render and every row reads as open.

The upstream findings API cannot filter by a Cloudsneeker table. The "Triage status" filter is therefore its own page instead of a findings query: `/triage` (`ui/app/(cloudsneeker)/triage/page.tsx`, sidebar entry under Cloud Security). It lists triaged findings by status, shows the latest note, and links each finding back to its check on the Findings page. A failed request shows a load error instead of an empty list.

When a status changes to `risk_accepted` or `false_positive`, the inherited UI also creates an upstream mute rule for the finding. That behavior is unchanged.

## Reports

The executive report adds `triage_in_progress` (`under_review` plus `remediating`), `triage_resolved`, and `triage_false_positive` to `kpis`, and the full counts to `extra["triage"]`. The counts cover triage rows whose UID appears in the in-scope scans.

The open-issue counts and the score are unchanged. A false positive still counts as open until it is muted.

## Known Gaps

* Rescans do not persist `reopened`. It is derived when the triage is read. A post-scan task that writes `reopened` with `source=automation` would need a hook in the upstream scan task.
* `filter[status]` matches the stored status. A derived `reopened` row is listed under `resolved`.
* Triage counts are not subtracted from executive open issues or the score. Decide with EB-021 how `false_positive` and `risk_accepted` affect them.
* The UI caps notes at 500 characters (`FINDING_TRIAGE_NOTE_MAX_LENGTH` in the inherited types). The API accepts 4000.
* The inherited UI edits the latest note in place. If someone else wrote that note, the API returns `403`.
* The UI does not hide the selector from roles without `manage_scans`. They get a `403` error when they save.
* The bulk endpoint has no UI yet. The inherited floating selection bar mutes and sends to Jira only.
