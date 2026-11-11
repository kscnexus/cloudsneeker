# Application Security Posture Management

Started 2026-11-10. Application Security moves from "scan a target, list that scan's rows" to posture management: applications own assets, findings persist across scans with a lifecycle and a priority, every scan stores a software inventory, and scans are driven by profiles and tenant policies. The scan engine stays Trivy (pinned in `api/Dockerfile`); static analysis stays OpenGrep.

What the engine supports and what the product implements, capability by capability, is in [Application Security Coverage](appsec-coverage.md). That page is generated from `cloudsneeker_api/appsec/capabilities.py`.

## Verification State

Read this before relying on the feature.

| Layer | State |
| --- | --- |
| Pure engine logic (capabilities, options, parser, risk, SBOM, failures, policies) | Unit tested; runs without a database |
| Execution (safe extraction, child process, timeout, cancel, retry, masking) | Unit tested with a real child process standing in for the scanner |
| Database code (models, migrations, lifecycle persistence, API) | Tests written in `tests/test_appsec_api.py`. **Not run on the development machine** (no test database there); they run in CI |
| Real engine runs | **None yet.** Report fixtures are built from the Go types of the pinned tag. A scan of each target type on a deployed worker is still required |
| UI | Type-check, lint and unit tests pass. Not exercised in a browser against a live API |

## Audit of the Previous Implementation

| Finding | Effect | Now |
| --- | --- | --- |
| Rows were written per scan into the shared `Finding` table; nothing persisted across scans | No new, fixed or reopened state; no history | `AppSecFinding` keeps one row per fingerprint and target |
| UID was `trivy-<mode>-<id>-<target>` cut at 300 characters | Several findings shared a UID (same check twice in a file, a package at two versions); long UIDs collided | Fingerprint is a SHA-256 of the identity; UIDs are unique per tenant |
| Only title, description and severity were mapped; the rest stayed in `raw_result` | Package, versions, CVSS, CWE, line numbers, resolution and license category were not queryable or shown | Columns for the common fields, `details` for the rest, unknown fields kept under `details.extra` |
| `UNKNOWN` severity was stored as `low` | Unknown-license and unscored findings read as low risk | `unknown` is its own value (the shared rows keep `low`, their scale has no other) |
| `Packages` were never read | No inventory, no SBOM, no component view | `AppSecSbom` and `AppSecComponent` per scan |
| The cluster report (`Resources[].Results`) was parsed as a plain report | Cluster scans imported no findings | Both shapes parsed |
| Cluster scans passed `--context` and a `cluster` argument | Neither exists at the pinned version; the scan failed | Kubeconfig by environment, optional context as the positional argument |
| Infrastructure as Code and image targets ran through the provider scan | A fixed scanner set; no packages or licenses | They run on the engine. A source that is a whole registry still uses the provider scan |
| The scan process inherited the worker environment | Database and Django secrets were visible to a process reading untrusted code | Allow-listed environment (`engine.ENV_PASSTHROUGH`) |
| Archives were unpacked with `extractall` | Path traversal and archive bombs | `engine.safe_extract`: no links, no paths outside the root, file-count and size limits |
| The comment said the engine exits non-zero when it finds vulnerabilities | Failures with an empty report were the only failures detected | No `--exit-code` is passed; exit 0 is success, anything else is classified from stderr |
| Run status was written inside the task transaction | `running` was never visible; a run looked queued until it ended | Run state is written through the admin connection and commits at once |
| No cancellation, no retry, no engine version, no stderr | Failures were not diagnosable | Recorded on `TrivyRun` (see below) |
| Scanner options were not exposed | No severity filter, skip paths, license or image options | Scan profiles and per-target options, validated against the capability matrix |

## Architecture

```
API (views_trivy, views_appsec)
  -> services.trivy.enqueue_trivy_run        validate, per-target and per-tenant limits
  -> Celery "scans" queue (existing)         cloudsneeker-trivy-scan
  -> appsec.engine.execute_run
       resolve_options      profile -> application -> tenant default -> built-in, then target overrides
       prepare_units        clone, extract, write document, kubeconfig; one unit per image
       policies             write tenant policy files, add flags
       run_process          argv list, allow-listed env, stdout and stderr files, timeout, cancel poll
       failures             classify exit code and stderr; retry database and network failures
       parser               JSON -> NormalizedFinding, NormalizedComponent
       mask + store_report  masked report, gzip, under DJANGO_TMP_OUTPUT_DIRECTORY/cloudsneeker-appsec
       persist_results      one transaction:
            lifecycle.reconcile     new / open / reopened / fixed, priority, deadline, events
            inventory.store_inventory  SBOM version and components
            trivy_import.import_trivy_report  shared Scan / Finding rows (unchanged contract)
  -> PostgreSQL (row-level security)
  -> UI (/application-security/...)
```

No second queue, worker, auth layer or settings system is added. Reports, alerts, area findings, triage and the outbound integrations keep reading the shared `Scan` / `Finding` rows, which every scan still writes.

### Modules

| Module (`api/src/backend/cloudsneeker_api/appsec/`) | Role | Database |
| --- | --- | --- |
| `capabilities.py` | Engine version, target and scanner matrix, option specs, built-in profiles, feature coverage | No |
| `options.py` | Option validation per target type, argument list construction | No |
| `parser.py` | Report parsing, fingerprints, secret masking | No |
| `risk.py` | Priority score with its factors; deadline defaults | No |
| `sbom.py` | Component summary, version comparison, CycloneDX document | No |
| `failures.py` | Failure classification, retry backoff | No |
| `policies.py` | Policy validation and the files a scan receives | No |
| `shared_rows.py` | Rows for the shared `Finding` table | No |
| `lifecycle.py` | Reconciliation, coverage rules, rescoring | Yes |
| `inventory.py` | SBOM and component storage, retention | Yes |
| `engine.py` | Execution, artifacts, exports | Yes |
| `queries.py` | Filters, serialization, dashboard figures | Yes |
| `maintenance.py` | Rescore and retention tasks | Yes |

## Data Model

Migration `0023_appsec_aspm` (tables and `TrivyRun` / `TrivyTarget` columns) and `0024_appsec_retention_periodic_task`. All tables are row-level security protected.

| Table | Holds |
| --- | --- |
| `cloudsneeker_appsec_applications` | Name, owner, criticality, environment, internet exposure, default profile |
| `cloudsneeker_trivy_targets.application_id` | The application an asset belongs to (nullable) |
| `cloudsneeker_appsec_scan_profiles` | Custom profiles (built-in profiles live in code) |
| `cloudsneeker_appsec_policies`, `..._policy_versions` | Tenant policy content and earlier versions |
| `cloudsneeker_appsec_settings` | Risk overrides, deadlines, retention, default profile per target type |
| `cloudsneeker_appsec_findings` | One finding per target and fingerprint: category, severity, rule, package, versions, location, CVSS, state, priority, deadline, first and last scan, `details` |
| `cloudsneeker_appsec_finding_events` | Detected, fixed, reopened, severity changed, suppressed |
| `cloudsneeker_appsec_sboms`, `..._components` | Inventory version per scan and its packages |
| `cloudsneeker_trivy_runs` (new columns) | Engine and version, profile, resolved options, redacted command, exit code, stderr tail, duration, attempts, database version, coverage, statistics, artifact path, cancel request |

Triage is not duplicated. `AppSecFinding.uid` is the UID of the shared `Finding` rows and of `FindingTriage`, so the existing triage routes, notes, bulk action and audit log apply.

## Finding Lifecycle

* **Fingerprint**. Vulnerability: advisory, package, package path, location. Misconfiguration: normalized check id, file, then the resource name, else a hash of the cause lines, else the line. Secret: rule, file, masked match, plus an ordinal for repeats. License: name, package or file, location. Code: rule, file, lines.
* **Left out on purpose**: installed version (an upgrade that is still vulnerable is the same finding), image tag and OS release in OS package results, line numbers when a resource name or cause text exists.
* **States**: `new` (first detection), `open` (seen again), `fixed`, `reopened`. Set only by scans.
* **Fixed needs evidence**. A finding missing from a scan becomes `fixed` only when the scan completed, ran the scanner for that category, reported that severity, was not limited to fixed vulnerabilities (for an unfixed one), and was not narrowed by a path, package, license or namespace option. `TrivyRun.coverage` records the decision and the reasons.
* **UID**. The legacy UID when no other finding of the tenant has it, else the legacy UID plus 12 fingerprint characters. Existing triage on a legacy UID therefore still applies.

## Priority

`risk.score_finding` returns 0 to 100 and the factors that built it: scanner severity (base), CVSS, EPSS and known-exploited (only when a source set them; none does today), fix available, direct dependency, application criticality, environment and exposure, age. Secrets have a floor. Thresholds and deadlines are tenant settings; changing them, or an application's context, queues `cloudsneeker-appsec-rescore`. The scanner severity is never rewritten.

## API

All under `/api/v1/`. The plan feature `application_security` gates every `appsec` and `trivy-` path. Reads follow provider visibility; writes need `manage_scans` and are recorded by the audit log middleware.

| Path | Methods | Purpose |
| --- | --- | --- |
| `appsec/overview` | GET | Dashboard figures |
| `appsec/capabilities` | GET | Target, scanner and option matrix; coverage |
| `appsec/engine` | GET | Engine version, vulnerability data, limits, queue, failures |
| `appsec/settings` | GET, PATCH | Risk, deadlines, retention, default profiles |
| `appsec-applications` | GET, POST, PATCH, DELETE | Application inventory (`target_ids` assigns assets) |
| `appsec-scan-profiles` | GET, POST, PATCH, DELETE | Profiles (built-in ones are read only) |
| `appsec-policies`, `appsec-policies/validate` | GET, POST, PATCH, DELETE | Policies; content changes create a version |
| `appsec-findings`, `/{id}`, `/summary`, `/export` | GET | Findings, detail with history and related findings, figures, CSV or JSON |
| `appsec-sboms`, `/{id}`, `/{id}/components`, `/{id}/compare?base=`, `/{id}/download?format=` | GET | Inventories |
| `appsec-components`, `/summary` | GET | Current inventory across assets |
| `trivy-runs/{id}/cancel` | POST | Stop a queued or running scan |
| `trivy-runs/{id}/export?format=` | GET | Stored report as JSON, SARIF, CycloneDX or SPDX |
| `trivy-targets` | unchanged | Adds `application_id`, `config.profile`, `config.options`, mode `rootfs` |
| `findings/<uid>/triage`, `finding-triages` | unchanged | Triage of an Application Security finding by its `uid` |

Existing contracts are unchanged: the new fields on `trivy-targets` and `trivy-runs` are additive.

## UI

`/application-security` routes (`ui/app/(cloudsneeker)/application-security/`). Helpers in `ui/cloudsneeker/lib/appsec.ts`, actions in `ui/cloudsneeker/actions/appsec.ts`, components `ui/cloudsneeker/components/appsec-*.tsx`.

| Route | Page |
| --- | --- |
| `/` | Overview: inventory, findings by category, severity and priority, trend, assets needing attention, vulnerable packages, inventory and scan execution |
| `/applications`, `/applications/new`, `/applications/<id>` | Application inventory, posture and assets |
| `/scans`, `/new`, `/<targetId>`, `/<targetId>/runs/<runId>` | Targets and scans (the previous hub); scan detail with coverage, lifecycle, exports, command and log |
| `/vulnerabilities`, `/misconfigurations`, `/secrets`, `/licenses`, `/code`, `/findings` | Finding workspaces, server-side filters and pagination |
| `/findings/<id>` | Finding detail, priority factors, triage, history, related findings |
| `/components` | Software composition |
| `/sboms`, `/sboms/<id>` | SBOM catalogue, components, comparison, download |
| `/profiles` | Scan profiles |
| `/settings` | Engine status, policies, prioritization and retention, supported matrix, coverage |
| `/triage` | Unchanged |

Downloads go through the same-origin proxy `ui/app/api/cloudsneeker/appsec/download/route.ts`, which only maps known kinds, formats and ids (`lib/appsec-download.ts`).

## Operations

Environment (platform level; not tenant editable):

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRIVY_HUB_TIMEOUT_SECONDS` | 900 | Scan timeout when the profile sets none |
| `TRIVY_HUB_MAX_CONCURRENT_PER_TARGET` | 2 | Active scans per target |
| `APPSEC_MAX_ACTIVE_RUNS_PER_TENANT` | 10 | Scans running at once per tenant; extra runs stay queued and are dispatched again every 30 s (`engine.execute_run`). Running rows older than timeout × attempts + 10 min do not count |
| `APPSEC_MAX_QUEUED_RUNS_PER_TENANT` | 1000 | Queued plus running scans per tenant; past it, starting a scan is refused |
| `APPSEC_ENGINE_MAX_ATTEMPTS` | 3 | Attempts for database and network failures |
| `APPSEC_MAX_REPORT_BYTES` | 512 MiB | Largest report read |
| `APPSEC_MAX_EXTRACTED_BYTES`, `APPSEC_MAX_EXTRACTED_FILES` | 2 GiB, 200000 | Archive limits |
| `APPSEC_MAX_IMAGES_PER_RUN` | 20 | Images in one scan |
| `APPSEC_ENGINE_DIRECT_MODES` | all | Target types the engine runs itself |

When a package registry rate-limits a scan (HTTP 429, typically Maven Central while many Java repositories scan at once, with a Retry-After of about 20 minutes), the engine retries once at once with `--offline-scan` instead of failing. The run completes but is recorded as incomplete with that reason, so findings it no longer reports are not marked fixed.

Raw reports are stored masked under `DJANGO_TMP_OUTPUT_DIRECTORY/cloudsneeker-appsec/<tenant>/<run>/`, which the API and the workers must share (same requirement as reports). The daily task `cloudsneeker-appsec-retention` deletes reports and long-fixed findings past the tenant's retention.

### Deployment

1. Deploy the API and worker image, then run migrations (`0019`, `0020`). Both add tables and nullable or defaulted columns; no existing row is rewritten.
2. Deploy the UI.
3. Run one scan per target type and check the scan detail page: engine version matches the pin, coverage is complete, findings and components appear.

### Rollback

* **Infrastructure as Code or image scans misbehave**: set `APPSEC_ENGINE_DIRECT_MODES=repo,fs,rootfs,sbom,k8s`. Those two types go back to the provider scan. Their findings then stop updating in the new workspaces until re-enabled.
* **Whole change**: redeploy the previous API, worker and UI images. The new tables and columns are unused by the old code and can stay. To remove them, migrate `cloudsneeker_api` back to `0018` (drops the new tables; shared `Scan` / `Finding` rows and triage are untouched).

### Known Effects on Existing Data

* Infrastructure as Code and image targets now produce `trivy-<mode>-...` UIDs. Triage set on the UIDs the provider scan produced for those targets no longer matches a current finding.
* Findings of scans made before this change are not backfilled into the new tables. The first scan of each target after deployment creates them (all `new`).

## Not Done

See the Missing and Partially Implemented rows in [Application Security Coverage](appsec-coverage.md). The larger ones: real-engine verification, virtual machine images, whole-registry inventory, exploit intelligence (EPSS, known-exploited) feed, license, SBOM and remediation-tracking PDF reports, assistant tools for the new data, dependency tree view, end-to-end browser tests.
