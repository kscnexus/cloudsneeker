---
name: cloudsneeker-feature
description: >
  Where and how to build a Cloudsneeker feature so an upstream Prowler merge does not overwrite it.
  Trigger: When adding a Cloudsneeker model, endpoint, task, page, navigation entry, or MCP tool; when a change needs an edit inside an upstream Prowler file; when adding client-visible text, URLs, or product names.
license: Apache-2.0
metadata:
  author: cloudsneeker
  version: "1.0"
  scope: [root, api, ui]
  auto_invoke:
    - "Adding a Cloudsneeker feature (model, endpoint, task, page, navigation)"
    - "Editing an upstream Prowler file for Cloudsneeker work (hooks)"
    - "Adding client-visible text, URLs, or product names (brand gate)"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

## Critical Rules

- ALWAYS put new behavior in a Cloudsneeker-owned directory (table below).
- ALWAYS call Prowler for sign-in, users, roles, API keys, SSO, provider credentials, scans, and findings. NEVER add a second login, user table, role system, or secret store.
- NEVER rename `prowler` packages, imports, JSON:API types, URL paths, tables, or Celery task names.
- NEVER change an existing check, its metadata, an existing migration, or the behavior of an existing route or page.
- NEVER hard-code the product name or a product URL. Read them from the brand modules.
- NEVER search-replace "Prowler" in source. Display copy in upstream files is rewritten at build time by `cloudsneeker/tools/rebrand.rules.toml`.
- NEVER commit `.env` or a credential file. NEVER push this tree to `prowler-cloud/prowler`.

## Where Code Goes

| Kind of change | Directory |
| --- | --- |
| Python extension, tools, deploy, public docs | `cloudsneeker/` |
| Models, serializers, views, tasks, migrations | `api/src/backend/cloudsneeker_api/` |
| Pages | `ui/app/(cloudsneeker)/` (public pages: `ui/app/(cloudsneeker-public)/`) |
| UI actions, components, types, navigation | `ui/cloudsneeker/` |
| MCP additions | `mcp_server/prowler_mcp_server/cloudsneeker/` |
| New security check | New folder under `prowler/providers/{provider}/services/{service}/` |
| Tests | `tests/cloudsneeker/`, `cloudsneeker_api/tests/`, Vitest files beside the UI source |

Code in these directories has the same shape as the Prowler component beside it. Read that component's `AGENTS.md` and its skill first (`prowler-api`, `django-drf`, `jsonapi`, `prowler-ui`, `react-19`, `nextjs-16`, `tailwind-4`, `typescript`). The map is `knowledge-base/coding-standards.md`.

## Steps

1. **Find the neighbor.** Open the closest existing file in the same Cloudsneeker directory and copy its shape. Read the feature's page in `knowledge-base/` if one exists (index: `knowledge-base/README.md`).
2. **Write the failing test** (`tdd` skill). Cover success, failure, and the empty or unauthorized case.
3. **API work** follows these conventions:
   - Table name starts with `cloudsneeker_` (`cloudsneeker_api.models.TABLE_PREFIX`). UUIDv4 key. Tenant data extends `RowLevelSecurityProtectedModel`.
   - JSON:API type starts with `cloudsneeker-` (`JSON_API_TYPE_PREFIX`). Route goes in `cloudsneeker_api/urls.py`.
   - Add a new migration under `cloudsneeker_api/migrations/`. Take the next free number after fetching `github/main`; two branches often pick the same one.
   - An `APIView` sets the tenant itself. A Celery task calls `set_tenant` and is queued with `transaction.on_commit`.
   - Run `python manage.py makemigrations --check --dry-run` from `api/src/backend` with `DJANGO_SETTINGS_MODULE=config.django.testing`. It must report nothing left to generate, and it needs no database.
4. **UI work** follows these conventions:
   - A sidebar entry goes in `ui/cloudsneeker/navigation.ts`.
   - Lists use the standard list kit and page patterns in `knowledge-base/design-system.md` and `knowledge-base/platform-integration/UI_STANDARD.md`. The three product areas (Cloud Security, Application Security, Governance) stay uniform.
   - No visible upstream product name, and no link to upstream docs.
5. **If an upstream file must change**, keep it to one registration line, mark the line with `cloudsneeker-hook`, and add a row to `knowledge-base/upstream-hooks.md` (see "Adding a Hook" there). Prefer a rebrand rule for copy and a brand field plus hook for structure.
6. **Run the placement check.** It lists every modified or deleted upstream file on the branch that `upstream-hooks.md` does not record. A file that already has a row passes, so also read your own diff of any recorded file:

   ```bash
   python skills/cloudsneeker-feature/assets/check_upstream_edits.py
   ```

7. **Run the brand gate** when the change adds client-visible text, a URL, a file name, or an identifier:

   ```bash
   python cloudsneeker/tools/rebrand.py --check
   python cloudsneeker/tools/brand_audit.py --source
   ```

8. **Document it.** Update or add the feature's page in `knowledge-base/` and its line in `knowledge-base/README.md`. A user-facing feature also needs its guide in `cloudsneeker/docs/`.
9. **Ship it** with the `cloudsneeker-ship` skill. The feature is unfinished until that skill's checks pass.

## References

- `knowledge-base/upstream-sync.md`: full placement table, and what must stay untouched
- `knowledge-base/upstream-hooks.md`: every recorded hook, and how to add one
- `knowledge-base/coding-standards.md`: style by area, and which skill to open
- `knowledge-base/feature-verification.md`: test, compatibility, and integration gates
