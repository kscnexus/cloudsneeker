# Components

## SDK (`prowler/`)

The SDK is the assessment engine. It targets Python 3.10+ and is managed with `uv`. Version 5.45.0.

```text
prowler/
├── lib/check/          # Check execution
├── lib/cli/            # Command-line interface
├── lib/outputs/        # JSON, CSV, HTML, ASFF, OCSF, and other writers
├── lib/mutelist/       # Mute lists
├── providers/          # One directory per provider
└── compliance/         # Framework JSON that maps checks to requirements
```

Provider directories in this tree:

`alibabacloud`, `aws`, `azure`, `cloudflare`, `e2enetworks`, `gcp`, `github`, `googleworkspace`, `huaweicloud`, `iac`, `image`, `kubernetes`, `linode`, `llm`, `m365`, `mongodbatlas`, `nhn`, `okta`, `openstack`, `oraclecloud`, `scaleway`, `stackit`, `vercel`.

`providers/common/` holds shared helpers and is not a scannable provider.

A provider package looks like this:

```text
prowler/providers/{provider}/
├── {provider}_provider.py
├── models.py
├── lib/
└── services/{service}/
    ├── {service}_service.py    # Fetches resources
    ├── {service}_client.py     # Singleton the checks import
    └── {check_name}/
```

Infrastructure-as-code scans delegate coverage to Trivy. LLM scans delegate to promptfoo. Those two providers do not carry a Cloudsneeker check-per-folder tree the way AWS does.

Tests live under `tests/`, mirroring the SDK layout. AWS tests use moto. Before adding a check or provider, read `skills/prowler-sdk-check/SKILL.md` or `skills/prowler-provider/SKILL.md`.

## API (`api/`)

Django 5.1, Django REST Framework, djangorestframework-jsonapi, Celery 5.4, PostgreSQL 16.

```text
api/src/backend/
├── api/           # Models, filters, RLS, v1 views and serializers
├── config/        # Settings and Celery app
└── tasks/         # Worker tasks
```

Important task names:

| Task name | Function | Queue |
| --- | --- | --- |
| `provider-connection-check` | `check_provider_connection_task` | default |
| `scan-perform` | `perform_scan_task` | `scans` |
| `scan-summary` | `perform_scan_summary_task` | `overview` |
| `attack-paths-scan-perform` | `perform_attack_paths_scan_task` | `attack-paths-scans` |
| `scan-report` | `generate_outputs_task` | `scan-reports` |
| `tenant-deletion` | `delete_tenant_task` | `deletion` |

OpenAPI annotations use `@extend_schema`. New tenant endpoints inherit `BaseRLSViewSet` and ship a filterset. Read `skills/prowler-api/SKILL.md` and `skills/jsonapi/SKILL.md` before changing the contract.

## UI (`ui/`)

Next.js 16, React 19, Tailwind 4, shadcn/ui, Zod 4, Zustand 5, NextAuth.

The signed-in application lives in `ui/app/(prowler)/`. Route group names do not appear in the URL. Main pages:

| Path | Page file |
| --- | --- |
| `/` | Overview |
| `/providers` | Connected accounts |
| `/scans` | Scan history and launch |
| `/findings` | Finding triage |
| `/resources` | Inventoried resources |
| `/compliance` | Framework posture |
| `/attack-paths` | Graph exploration |
| `/lighthouse` | AI assistant |
| `/mutelist` | Mute rules |
| `/integrations` | Jira, Slack, Amazon S3, Security Hub |
| `/users`, `/roles`, `/invitations` | Access management |

UI code follows a strict split: server actions in `actions/`, adapters next to those actions, shared types in `types/`, shared hooks in `hooks/`, primitives in `components/shadcn/`. React Compiler is on, so components do not add `useMemo` or `useCallback`. Read `skills/prowler-ui/SKILL.md` before editing components.

`siteConfig.name` in `ui/config/site.ts` reads `BRAND.name` from `ui/cloudsneeker/brand.ts`; every other product string and external URL in the UI comes from that module too. Cloudsneeker-only pages live in `ui/app/(cloudsneeker)/` (for example `/about`) and register their sidebar entries in `ui/cloudsneeker/navigation.ts`.

## MCP Server (`mcp_server/`)

Python 3.12+ and FastMCP. The server mounts three sub-servers:

* `prowler_hub` — catalog and compliance tools, no auth
* `prowler_docs` — documentation search, no auth
* `prowler` — Local Server and cloud management, auth required

Tools that call the API subclass `BaseTool` and use the shared `ProwlerAPIClient`. They return simplified Pydantic models, not raw JSON:API payloads. Read `skills/prowler-mcp/SKILL.md` before adding a tool.

## Dashboard (`dashboard/`)

A Dash and Plotly app for local CLI output. It is separate from the Next.js UI. Launch it with `prowler dashboard` after a CLI scan.

## Skills and Agent Guides

`skills/*/SKILL.md` is the pattern library. Root and component `AGENTS.md` files say which skill to open for which action. `skills/setup.sh` symlinks those skills into Claude Code, Gemini CLI, Codex, and Copilot layouts. Cursor reads `AGENTS.md` directly.

When a skill and this knowledge base disagree about a command or path, trust the skill and the code, then update this knowledge base.
