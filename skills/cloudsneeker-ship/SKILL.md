---
name: cloudsneeker-ship
description: >
  Ships a Cloudsneeker change: local checks, pull request, CI, automatic deploy, and verification on the deployed site.
  Trigger: When a Cloudsneeker change is ready to test, merge, deploy, or verify live; when a deploy or the uptime check fails.
license: Apache-2.0
metadata:
  author: cloudsneeker
  version: "1.0"
  scope: [root]
  auto_invoke:
    - "Shipping a Cloudsneeker change (PR, CI, deploy)"
    - "Verifying a Cloudsneeker change on the deployed site"
    - "Rolling back a Cloudsneeker release"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

## Critical Rules

- A change is verified only when it works on the deployed site. A local run is not the verification.
- The database-backed API suites and the full UI suites run in CI ("Cloudsneeker: Tests"). Do not start Docker, `next dev`, or Playwright on a developer PC to verify a change.
- NEVER weaken or delete an existing test to get a green run.
- NEVER force-push. NEVER commit `.env`, credentials, or fixture passwords.
- NEVER create test users, seed data, or change operator grants on the public site without the owner's say-so.
- Push only to the `github` remote. The `upstream` remote is fetch-only.

## Release Path

| Stage | What runs |
| --- | --- |
| Pull request to `main` | "Cloudsneeker: Tests": SDK, API with a database, UI, and MCP suites |
| Merge to `main` | Tests again; Vercel builds the web app (about 11 minutes) |
| After tests pass | "Cloudsneeker: Deploy to Azure" scans the images, then rebuilds and restarts the backend; migrations run on API start |
| Every 30 minutes | "Cloudsneeker: Uptime" probes the API and the sign-in page |

Hosts come from the repository variables `CLOUDSNEEKER_API_HOST` and `CLOUDSNEEKER_UI_URL`. Details and rollback: `knowledge-base/platform-integration/DEPLOYMENT_AND_ROLLBACK.md`.

## Steps

1. **Run the checks that work without a database.**

   ```bash
   python skills/cloudsneeker-feature/assets/check_upstream_edits.py
   python cloudsneeker/tools/rebrand.py --check
   python cloudsneeker/tools/brand_audit.py --source
   uv run pytest tests/cloudsneeker -q
   ```

   For UI changes also run `pnpm typecheck`, the lint, and the Vitest files beside the changed source from `ui/`. For API changes run `python manage.py makemigrations --check --dry-run` from `api/src/backend` with `DJANGO_SETTINGS_MODULE=config.django.testing`; it needs no database. Windows limits are in `knowledge-base/feature-verification.md`.

2. **Commit** with the `prowler-commit` skill. One logical change per commit.
3. **Push the branch to `github` and open a pull request** with the `prowler-pr` skill. Pass `--repo` with the owner and name of the `github` remote on every `gh` command; without it `gh` can resolve to the upstream repository. State what was verified and what was not.
4. **Wait for "Cloudsneeker: Tests".** Read a failing job's log before changing anything. A failure in an auth, provider, scan, finding, or integration suite is a break in this change, even when the new tests pass.
5. **Take a database dump first** when the change carries a migration that alters or drops existing data (the nightly dump is not enough for that case).
6. **Merge.** Wait for the Vercel build and for "Cloudsneeker: Deploy to Azure" to finish. A blocked image scan means a new CVE: read the scan report artifact, then bump the pin or record an accepted finding in `cloudsneeker/deploy/trivy/accepted-vulnerabilities.yaml`.
7. **Check the deployed site.** Set the two hosts first: read them with `gh variable list --repo <owner>/<name>`, or take the defaults in `.github/workflows/cloudsneeker-uptime.yml`.

   ```bash
   export CLOUDSNEEKER_API_HOST=<api host>
   export CLOUDSNEEKER_UI_URL=<web app url>
   curl -s -o /dev/null -w "%{http_code}\n" --max-time 20 "https://$CLOUDSNEEKER_API_HOST/health/live"
   python -I cloudsneeker/qa/live_probe.py --ui "$CLOUDSNEEKER_UI_URL" --api "https://$CLOUDSNEEKER_API_HOST" --out results.json
   ```

   Then walk the changed flow signed in, in a browser, on the deployed web app: the success path, one failure path, and the page at phone width. Use an account the owner provided.

8. **Report plainly.** List what passed live, what was not exercised (for example a real identity provider, a real Slack workspace, outbound email), and anything left for the owner.
9. **Record it.** Add the change to `knowledge-base/platform-integration/IMPLEMENTATION_CHANGELOG.md`. If it closes a backlog item, finish with the `cloudsneeker-backlog` skill.

## Rollback

| Scope | Action |
| --- | --- |
| Web app only | Promote the previous Vercel deployment |
| API and worker | Revert the merge commit on `main`; the deploy workflow redeploys |
| Schema | Old code ignores added tables and columns. Reverse a migration only when the revert needs it, and say what data that deletes |
