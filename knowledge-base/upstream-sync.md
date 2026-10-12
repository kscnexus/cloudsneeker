# Upstream Sync

Cloudsneeker tracks [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler). New Prowler features arrive by merging that project's release tags. Cloudsneeker features stay in their own directories so that merge does not have to replay them, and client-visible copy is rewritten at build time so upstream files stay byte-identical in source.

## Remotes

| Remote | Points at | Use |
| --- | --- | --- |
| `upstream` | `https://github.com/prowler-cloud/prowler.git` | Fetch tags and merge. Never push. |
| `origin` | the private Cloudsneeker repository | Push branches, open pull requests, run CI. |

```bash
git remote add upstream https://github.com/prowler-cloud/prowler.git   # once
git remote add origin <private-cloudsneeker-remote>                     # once
git fetch upstream --tags
```

`cloudsneeker/tools/sync-upstream.ps1` refuses to run without the `upstream` remote.

## Where New Work Goes

| Kind of change | Location | Why a merge survives |
| --- | --- | --- |
| Product feature in Python | `cloudsneeker/` | Upstream has no such directory |
| New API models and endpoints | `api/src/backend/cloudsneeker_api/` | Own Django app, registered by one hook; routes under `/api/v1/cloudsneeker/` |
| New screens | `ui/app/(cloudsneeker)/` with `ui/cloudsneeker/` (actions, components, types, `navigation.ts`) | New route group that re-exports the upstream layout |
| MCP additions | `mcp_server/prowler_mcp_server/cloudsneeker/` | Own package |
| New security check | New folder under `prowler/providers/{provider}/services/{service}/` | A new directory merges cleanly |
| Product identity (names, URLs, prefixes, flags) | Brand modules: `cloudsneeker/brand.py`, `api/src/backend/cloudsneeker_api/brand.py`, `ui/cloudsneeker/brand.ts`, `mcp_server/prowler_mcp_server/cloudsneeker/brand.py` | Upstream files read them through one-line hooks |
| Display copy in upstream files | `cloudsneeker/tools/rebrand.rules.toml` | Applied to a build-tree copy, never to source |
| Documentation | `cloudsneeker/docs/` (guides) plus generated check and framework pages from `cloudsneeker/tools/gen_check_docs.py` | Upstream `docs/` is untouched |
| Deployment | `cloudsneeker/deploy/` (compose, Dockerfiles, Helm) and `.github/workflows/cloudsneeker-release.yml` | Upstream compose files and workflows are untouched |

Every edit that still has to land in an upstream file is a hook. Record it in [Upstream Hooks](upstream-hooks.md).

## Security and Admin Stay on Prowler

Cloudsneeker screens and endpoints use Prowler's security and admin stack. Pulling a new Prowler version updates that stack in place.

| Capability | Prowler owner |
| --- | --- |
| Authentication | NextAuth in `ui/auth.config.ts` and `ui/proxy.ts`; API `tokens`, `tokens/refresh`, and `tokens/switch` |
| Admin | `User`, `Membership`, invitations, `Role`, provider groups |
| Credentials | `Provider` and `ProviderSecret` |
| Client stores | `ui/store/` for session, providers, scans, roles, and the provider wizard |
| Audit | `Scan`, `Finding`, `Task`, mute rules, and report jobs |

A Cloudsneeker feature checks the Prowler session and role, then reads or writes those APIs. It does not add a login, a user table, a role system, a secret store, or an audit log of its own. `cloudsneeker_api.views.BrandView` is the reference shape: `CombinedJWTOrAPIKeyAuthentication`, `IsAuthenticated`, JSON:API document, no new state.

## What Must Stay Untouched

Leave these as Prowler owns them:

* Package name `prowler`, imports, and module paths; the Django apps `api`, `config`, `tasks`; `prowler_mcp_server`
* Auth, admin, credential, store, and audit code listed above
* JSON:API resource types, existing URL paths, and Celery task names
* Database table names and migrations that already shipped
* Existing check modules, metadata, and tests
* Docker entrypoints, container users (`/home/prowler`), `PROWLER_*` environment variables, Neo4j labels
* `NOTICE` and `LICENSE` (Apache 2.0 attribution to Prowler stays)

A bugfix that belongs in Prowler can edit the upstream file directly. Match upstream style, and expect that file to conflict on the next merge. Prefer sending that fix upstream rather than carrying a private behavior change.

## Merge Steps

1. Commit or stash Cloudsneeker work. Leave `.env` unstaged; it is never committed.
2. Run `pwsh cloudsneeker/tools/sync-upstream.ps1 -Tag <upstream tag>` (defaults to the newest tag). It fetches `upstream`, merges the tag with `--no-ff`, and stops on conflicts.
3. For each conflict, keep the upstream side of the file, then re-apply the hook rows for that file from [Upstream Hooks](upstream-hooks.md). Run `rg -n "cloudsneeker-hook" <file>` on the pre-merge version when in doubt.
4. Commit and run the script again. It then runs:
   * `python cloudsneeker/tools/rebrand.py --check` — fails when a rule no longer matches anything (upstream moved or reworded the text). Fix the rule and the fixture in `tests/cloudsneeker/tools/rebrand_test.py`, or retire it.
   * `python cloudsneeker/tools/brand_audit.py --source` — Cloudsneeker-owned directories still carry no upstream names.
   * The Cloudsneeker suites: `tests/cloudsneeker`, `api/src/backend/cloudsneeker_api`, the UI brand and config tests.
5. Run the component suites from [Local Development](local-development.md) and [Feature Verification](feature-verification.md). Upstream suites run with the upstream-compatible brand (`cloudsneeker.testing.UPSTREAM_COMPAT_ENV`, `ui/vitest.setup.ts` mock), so they should pass unchanged; a failure there usually means a hook was lost.
6. Rebuild the docs: `python cloudsneeker/tools/gen_check_docs.py`, then `python cloudsneeker/tools/brand_audit.py --tree cloudsneeker/docs`. New upstream checks and frameworks get pages automatically; new providers need a label in `PROVIDER_LABELS`.
7. Build the release through `cloudsneeker/deploy` or the `cloudsneeker-release` workflow. The build applies the transform to a copy of the tree and audits it; source stays upstream-identical.
8. Smoke the product: sign in, add a provider, run a scan, download CSV and PDF, open `/api/v1/docs`, decode a JWT (`iss`/`aud`), open `/about`, inspect a Slack or Jira test payload.

If a hook's upstream file moved, update the hook row. Do not re-introduce the old Cloudsneeker edit on top of the new upstream file.

## New Upstream Surfaces

After a merge, grep the diff for new client-visible strings and hosts that the rules do not cover yet:

```bash
git diff <old-tag>..<new-tag> --stat
python cloudsneeker/tools/rebrand.py --check
robocopy . "$env:TEMP\cs-tree" /MIR /XD .git node_modules .venv .next _data   # or rsync
python cloudsneeker/tools/rebrand.py --apply --root "$env:TEMP\cs-tree"
python cloudsneeker/tools/brand_audit.py --tree "$env:TEMP\cs-tree"
```

Each audit hit is either a new rule, a new hook with a new brand field, or an allowlist entry in `cloudsneeker/tools/brand_audit.allow.toml` when the text is an internal identifier that clients never see.
