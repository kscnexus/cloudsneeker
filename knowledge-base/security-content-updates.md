# Keeping Security Content Current

Cloudsneeker's value to customers depends on fresh detection content: cloud
posture checks, compliance mappings, CVE data, code rules and governance
policies. This page says where each kind of content comes from, how it is
updated, and who owns the update.

## Content sources

| Content | Source | Where it is pinned | How it updates today |
| --- | --- | --- | --- |
| Cloud posture checks (AWS, Azure, GCP, Kubernetes, M365, GitHub, ...) | Upstream Prowler checks under `prowler/providers/**` | The merged upstream release tag | Merge an upstream release ([Upstream Sync](upstream-sync.md)), then CI rebuilds and deploys |
| Compliance frameworks and mappings (CIS, NIST, ISO 27001, PCI DSS, ...) | Upstream `prowler/compliance/**` | Same upstream tag | Same as checks |
| Vulnerability (CVE) database for dependencies, containers, SBOM, Kubernetes | Trivy vulnerability DB (published several times a day) | Not pinned | Downloaded by each Application Security scan into the task's temporary cache. Always fresh, but every scan pays the download and depends on the DB registry being reachable |
| Trivy engine | `TRIVY_VERSION` in `api/Dockerfile` | Build argument | Bump the version, CI rebuilds |
| IaC, secret and misconfiguration rules (Trivy built-in) | Ship with the Trivy version and its checks bundle | `TRIVY_VERSION` | Bump with the engine |
| SAST rules | GitLab sast-rules, `SAST_RULES_REF` and `SAST_RULES_SHA256` in `cloudsneeker/deploy/docker/api.Dockerfile` | Tag and checksum | Bump both, check the license of new folders (see [Product Redesign Plan](product-redesign-plan.md) Phase 3), CI rebuilds |
| SAST engine | `OPENGREP_VERSION` and its checksum in the same Dockerfile | Build argument | Bump, CI rebuilds |
| Governance policies (dry-run) | Cloud Custodian (`C7N_*` versions) plus Cloudsneeker starter templates in `api/src/backend/cloudsneeker_api/services/custodian_templates.py` | Build arguments and repository code | Bump versions; add or edit templates in code |
| Attack Paths graph | Cartography version in `api/pyproject.toml` | Lockfile | Dependency bump |

## Recommended cadence

| When | Task | Owner |
| --- | --- | --- |
| Continuous | CVE data: already fresh on every scan. Watch the Application Security run errors for DB download failures | Platform on-call |
| Weekly | Review new upstream Prowler releases and security advisories; bump Trivy if a release fixes detection gaps | Detection engineer |
| Every upstream minor release (about monthly) | Merge the upstream tag with `cloudsneeker/tools/sync-upstream.ps1`, re-apply hooks per [Upstream Hooks](upstream-hooks.md), run the full CI suite (`cloudsneeker-tests.yml` via `workflow_dispatch`), deploy, and spot-check one scan per provider | Engineering |
| Quarterly | Bump SAST rules and OpenGrep after a license review; review Custodian starter templates against new cloud services | Detection engineer |
| Each release | Write customer-facing release notes: new checks, changed frameworks, removed checks (these change scores) | Product |

Score changes: new checks and framework revisions move customer scores and
compliance percentages. Announce them in release notes before the release
lands, so a customer's executive report does not show an unexplained drop.

## Per-customer tuning (no code change)

These settings live in each customer's organization and are kept by the
managed-service team:

- **Scan profiles** (Scans → Scan profiles): per-provider overrides of check
  settings, for example password age or allowed regions.
- **Mutelist** (Configuration → Mutelist): accepted exceptions. Record the
  reason and an owner in the rule description; review quarterly.
- **Finding triage** (Findings and Cloud Security → Triage): statuses such as
  risk accepted or false positive, with notes, carried across rescans.
- **Scan schedules**, alert rules and report schedules: cadence per customer
  contract (for example a monthly executive report).
- **Application Security targets**: rule packs and exclude globs per
  repository for SAST; scanners per target for the other modes.
- **Governance policies**: per-customer policies created from the starter
  templates; dry-run only.

## Custom content

- **A new posture check for every customer**: add it as a new folder under
  `prowler/providers/{provider}/services/{service}/` (see the
  `prowler-sdk-check` skill). New folders merge cleanly with upstream.
- **A customer-only rule**: use a governance policy or a scan profile setting
  for that organization rather than a global check.
- **A new compliance framework or an internal control set**: add a framework
  JSON (see the `prowler-compliance` skill), mapped to existing checks.

## Gaps tracked in the backlog

- EB-047: shared vulnerability DB cache on EFS with a scheduled refresh, so
  scans stop downloading the DB each run and keep working if the registry is
  briefly unreachable.
- EB-048: an in-app "Content versions" panel showing the posture content
  release, CVE DB age, SAST rules version and engine versions, so customers
  and auditors can see how current detection is.
- EB-049: release-notes feed in the app that lists new and changed checks per
  release.
