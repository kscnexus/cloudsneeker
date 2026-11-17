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

```text
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
| `appsec-source-connections`, `/{id}/repositories`, `/{id}/import` | GET, POST | GitHub connections as code sources (see Code sources) |
| `trivy-targets/{id}/merge` | POST | Fold duplicate targets of the same source into this one |
| `appsec/repository-branches?provider_id=` | GET | Branches of a code repository source, default first (`manage_scans`; 502 when the repository cannot be read) |
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

### Branches

Repository and static analysis targets that read a Git URL have a **main branch**: `config.branch`, or the repository's default branch when it is empty (every target created before this setting). The create form lists the source's branches (`git ls-remote` with the source's token or SSH key, `services/repo_branches.py`).

One target also covers **other branches** (`services/branch_policy.py`):

* `config.branches` lists branch names or glob patterns (`develop`, `release/*`; at most 50).
* A scan queues the main-branch run, then Celery `cloudsneeker-appsec-branch-runs` lists the remote branches with their head commits and queues one run per matching branch (`TrivyRun.branch`). A branch whose head commit is the one its latest completed run scanned (`summary.commit`) is skipped. At most `APPSEC_MAX_BRANCHES_PER_SCAN` (default 20) branches are queued per scan.
* `POST /trivy-targets/{id}/scan` takes `branch` (scan one branch now, listed or not) or `all_branches: true` (queue every matching branch, changed or not).
* Other-branch findings are stored with `AppSecFinding.branch` set. Every list, figure and report reads the main branch (`branch` empty) unless the findings API is asked with `filter[branch]=<name>` or `*`. The summary returns `branches`, the other branches with findings, for the picker on the findings pages.
* Only main-branch runs write the shared `Scan` / `Finding` rows and the inventory, so reports, alerts and the S3, Security Hub, Jira and Slack integrations keep following the main branch. Other-branch triage is separate (a different UID).
* Targets created before this, one per branch, can be merged (below).

* SSH repositories are cloned with that branch (`depth=1`); HTTPS repository scans pass it as the engine's branch option. `config.branch` replaces any branch, tag or commit from a profile or `config.options`.
* Each run records the branch it scanned in `summary.branch` (the default branch is read from the clone's `HEAD`), and `trivy-runs` returns it as `branch`. Findings carry `target_branch` (empty: default branch).
* The branch is part of the target name (`<name> @ <branch>`), so every list, finding, report row, export, SBOM and scan name shows it. The API keeps the name in step: saving a branch adds it, changing it replaces it (`name_for_branch` in `services/repo_branches.py`).
* Targets saved without a branch get it recorded (config and name) after their first scan, or at once with **Record branches** on the Scans page (`POST /appsec/record-branches`, Celery `cloudsneeker-appsec-record-branches`). That uses the branch the latest run recorded, else the repository's current default branch. A recorded branch is then fixed: if the repository's default branch changes later, edit the target. If the new name is already taken, the target keeps its old name.
* Per-target SCA and SAST reports are titled and named `<target> @ <branch>`, so files read `<target>-<branch>-sca-<date>.pdf`. A default-branch target uses the branch its latest completed run recorded.

### Static analysis in the repository target

A code repository target runs static analysis in the same run when `config.sast` is set (`{"rulesets": [...], "exclude": [...]}`; `true` means automatic rule sets). No second static analysis target is needed for the same repository.

* The engine runs, then OpenGrep clones the same branch and runs (`engine.run_code_step`). A static analysis failure is recorded in `summary.sast` and never discards the dependency results.
* Coverage is per engine (`lifecycle.CombinedCoverage`): a failed static analysis step closes no code findings, and a failed dependency scan closes no dependency findings.
* The static analysis rows go to a second shared scan with mode `sast` (`TrivyRun.code_scan_id`), so report streams, area findings, mute rules and alerts treat them exactly like a static analysis target's rows.
* "Scan all repositories" creates one code repository target per repository with static analysis on. If a static analysis target already exists for that repository, the new target leaves static analysis to it.
* The `sast` target type stays for uploaded code archives.

### Merging duplicate targets

`POST /trivy-targets/{id}/merge` with `source_target_ids` folds other targets of the same source into this one (`services/target_merge.py`), in one transaction:

* A static analysis target turns `config.sast` on with its rule sets; its runs keep their shared rows as `code_scan_id`.
* A target of another branch becomes one of `config.branches`; its findings keep that branch.
* Findings, events and runs move; triage follows the unchanged UID. The source's inventory versions are dropped. Report schedules that named the source name the kept target.
* Refused (409) for another source, an archive target, or findings that already exist on the same branch of the kept target.

The target page lists the candidates under **Duplicate targets of this repository**.

### Code sources from a GitHub connection

A GitHub provider (the posture connection) is also the source of code repositories (`services/github_source.py`, page **Scan setup → Code sources**):

* `GET /appsec-source-connections` lists GitHub connections with the repositories imported from each.
* `GET /appsec-source-connections/{id}/repositories` lists the repositories the connection can read (token: `/user/repos`; GitHub App: an installation token, `/installation/repositories`). Needs `manage_providers`.
* `POST /appsec-source-connections/{id}/import` with `clone_urls` creates an IaC provider per repository and links it (`RepositoryConnection`). A repository already added is linked instead.
* A token connection's token is copied to the repository's own secret (so upstream paths that read provider secrets work) and the copy is refreshed when the connection's secret changes (`signals._provider_secret_saved`). A GitHub App token expires within the hour, so it is never copied: `trivy._repo_credentials` mints one when the repository has no token of its own.
* Every create form picks its source with the same grouped picker (`components/source-picker.tsx`): repositories under the GitHub connection they came from, the rest by type.

Not done: GitHub Enterprise Server hosts (the GitHub provider has no host field), and grouping imported repositories under their connection on the upstream Providers page.

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
