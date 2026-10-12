# Local Development

Commands below run from the repository root unless a directory is shown. Python dependencies install with `uv`. The UI uses `pnpm`.

## Full Stack

```bash
docker compose -f docker-compose-dev.yml up
```

`docker-compose.yml` pulls published `prowlercloud` images. Use the dev compose file when you need local code and hot reload.

Default endpoints after the stack is healthy:

| Surface | URL |
| --- | --- |
| UI | http://localhost:3000 |
| API | http://localhost:8080/api/v1 |
| API liveness | http://localhost:8080/health/live |
| MCP server | http://localhost:8000 |

Copy `.env` from the example the compose file expects, and replace default passwords before any shared or production use. Do not commit `.env`.

## SDK and CLI

```bash
uv sync
uv run prek install
uv run python prowler-cli.py aws --list-checks
uv run python prowler-cli.py aws --check <check_name>
uv run pytest tests/
```

`prek` runs the same hooks as CI (format, lint, and security checks). `uv run make lint` and `uv run make format` cover the Python tree.

## API

PostgreSQL, Valkey, and Neo4j can run in Docker while Django and Celery run on the host:

```bash
make dev-setup    # dependencies, migrations, fixtures
make dev          # API, worker, and database logs in tmux
make dev-stop
```

`make dev` targets macOS and Linux. On Windows, start the data services with Docker and run Django yourself:

```bash
cd api
uv run python src/backend/manage.py runserver
uv run celery -A config.celery worker -l INFO
uv run pytest
```

The API process listens on port 8080. The UI is not part of `make dev`; start it separately.

Schema changes go through Django migrations. Read `skills/django-migration-psql/SKILL.md` before running `makemigrations`. Tenant tables need RLS policies, not only a new model field.

## UI

```bash
cd ui
pnpm install
pnpm run dev
pnpm run typecheck
pnpm run lint:fix
pnpm run healthcheck
```

Playwright end-to-end tests live under `ui/tests/`. Unit tests use Vitest. UI work in this repository follows test-first development: read `skills/tdd/SKILL.md` and `skills/vitest/SKILL.md` before changing a component.

## MCP Server

```bash
cd mcp_server
uv run prowler-mcp --transport http --port 8000
uv run pytest
```

From the root, `make test-mcp` matches the CI invocation.

## Documentation Site

User docs are Mintlify MDX under `docs/`. Preview them with the pinned CLI:

```bash
npm install --global mint@4.2.689
cd docs
mint dev
```

The preview listens on http://localhost:3000, which collides with the UI dev server. Run one at a time, or change the port. Writing for `docs/` follows `docs/AGENTS.md` (title case headings, defined acronyms, verbal constructions). This knowledge base is internal and is not part of the Mintlify navigation.

## Commit Shape

Use conventional commits: `feat`, `fix`, `docs`, `chore`, `perf`, `refactor`, `style`, `test`. Optional scope, for example `feat(ui): ...`. Changelog fragments for user-visible SDK, API, UI, and MCP changes follow `skills/prowler-changelog/SKILL.md`.

## Pointers

| Need | Open |
| --- | --- |
| Product name versus code identifiers | [Product and Naming](product-and-naming.md) |
| Services and data stores | [Architecture](architecture.md) |
| How a scan is queued and stored | [Scan Lifecycle](scan-lifecycle.md) |
| Directory map | [Components](components.md) |
| Coding patterns | `skills/<name>/SKILL.md` and the nearest `AGENTS.md` |
