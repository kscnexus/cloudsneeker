# Scan Lifecycle

A scan is the unit of work that turns provider credentials into findings. The CLI can run that work in-process. The Local Server always runs it on a Celery worker so the API request stays short.

## Domain Objects

These models in `api/src/backend/api/models.py` are the ones a scan touches.

| Model | Role |
| --- | --- |
| `Provider` | Connected account, subscription, project, cluster, or tenant to scan |
| `ProviderSecret` | Stored credentials for that provider |
| `Scan` | One execution against a provider, with state and timing |
| `Task` | Link from a scan to the Celery task id |
| `Resource` | An inventoried cloud resource |
| `Finding` | One check result (PASS, FAIL, MANUAL, or muted) |
| `ResourceFindingMapping` | Join between a finding and the resources it cites |
| `ScanSummary` and related summaries | Aggregates the UI overview and compliance pages read |
| `MuteRule` | Suppresses matching findings |
| `AttackPathsScan` | Graph ingestion that follows an AWS scan |

`Finding` is partitioned. Filters and writes must stay compatible with that partitioning.

## Local Server Path

1. The UI creates or selects a `Provider` and stores a `ProviderSecret`.
2. A connection check can run first: Celery task `provider-connection-check` (`check_provider_connection_task`).
3. Starting a scan creates a `Scan` in the queued state and a `Task` row. `enqueue_scan_execution_on_commit` dispatches work only after the database transaction commits.
4. The worker runs `scan-perform` (`perform_scan_task`) on the `scans` queue. That task calls the SDK (`perform_prowler_scan`) inside an RLS transaction for the tenant.
5. The SDK authenticates to the provider, loads the selected services, and executes each check. A check returns a list of reports with status and `status_extended`.
6. The worker writes findings, resources, and mappings into PostgreSQL.
7. Completion hooks in `_perform_scan_complete_tasks` enqueue follow-up work:
   * `scan-summary` on the `overview` queue refreshes overview aggregates
   * `generate_outputs_task` writes report files under the shared output directory
   * For AWS, `perform_attack_paths_scan_task` ingests the Attack Paths graph
8. Scheduled scans use `perform_scheduled_scan_task`. Beat enqueues them. The same provider does not run two scans at once; the next queued scan is dispatched when the active one finishes.

Long work belongs on Celery. A view should stay under roughly 100 ms. Tasks use `@shared_task` with an explicit `name` and `queue`, and tenant-scoped tasks use the `RLSTask` base class.

## CLI Path

The CLI entry point is `prowler-cli.py`, which loads the `prowler` package. A typical invocation is:

```bash
uv run python prowler-cli.py aws --check <check_name>
```

The CLI uses the same provider, service, and check classes as the worker. It writes outputs locally (JSON, CSV, HTML, and provider-specific formats such as ASFF and OCSF) instead of inserting `Finding` rows.

## Check Shape

Each check is a class under:

```text
prowler/providers/{provider}/services/{service}/{check_name}/
├── {check_name}.py
└── {check_name}.metadata.json
```

The class subclasses `Check`, reads a service client singleton, and returns `CheckReport{Provider}` objects. Metadata JSON holds the title, severity, description, and remediation text. Compliance frameworks under `prowler/compliance/` map requirement ids to these check ids. They do not reimplement the check.

## Status Values

| Status | Meaning |
| --- | --- |
| `PASS` | The resource matches the recommended configuration |
| `FAIL` | The resource needs a change |
| `MANUAL` | A person must confirm the result |
| Muted | A mute list or `MuteRule` suppressed the finding |

The CLI banner prints those states in color. The UI uses the stored finding status and severity.
