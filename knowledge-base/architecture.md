# Architecture

Cloudsneeker is a monorepo. The SDK performs assessments. The API stores tenants, providers, scans, and findings. The UI reads and writes that API. Workers run scans asynchronously. PostgreSQL holds relational data, Valkey backs the task queue, and Neo4j holds Attack Paths graphs.

```text
Browser
  │
  ▼
UI (Next.js, port 3000)
  │  JSON:API
  ▼
API (Django, port 8080) ──► PostgreSQL 16
  │
  │  enqueue
  ▼
Valkey 8 ──► Celery worker / beat
                │
                ├── SDK scan (prowler package)
                ├── output files (shared volume)
                └── Attack Paths ingest ──► Neo4j (Bolt 7687)

MCP server (HTTP, port 8000) ──► API
```

## Compose Services

`docker-compose.yml` is the production-shaped stack and pulls `prowlercloud/*` images. `docker-compose-dev.yml` is the local-build stack. Both describe the same roles.

| Service | Role | Default port |
| --- | --- | --- |
| `ui` | Next.js web application | 3000 |
| `api` | Django REST API | 8080 |
| `worker` | Celery worker that runs scans and follow-up jobs | — |
| `worker-beat` | Celery beat for scheduled scans | — |
| `mcp-server` | MCP HTTP server (`uvicorn` on 8000) | 8000 |
| `postgres` | PostgreSQL 16 | 5432 |
| `valkey` | Queue and cache (Redis-compatible) | 6379 |
| `neo4j` | Graph database for Attack Paths (DozerDB image) | 7687 |
| `api-init` | One-shot ownership fix for the API data volume | — |

The API health check is `GET /health/live`. The UI health check is `GET /api/health`. The MCP health check is `GET /health`.

Persistent data lives under `_data/` for Postgres, Valkey, Neo4j, and API config. Scan output files share the `output` volume at `/tmp/prowler_api_output`.

## Tenancy

Almost every business record belongs to a tenant. Tenant-scoped Django models inherit `RowLevelSecurityProtectedModel`. PostgreSQL row-level security (RLS) enforces the boundary. Application code opens that scope with the `rls_transaction(tenant_id)` context manager. Do not query across tenants, and do not trust a tenant id supplied only by the client.

Primary keys are UUIDv4. Models carry `inserted_at` and `updated_at`. Findings and resource-finding mappings are partitioned Postgres models because those tables grow with every scan.

## API Contract

The API speaks JSON:API v1.1.

* Content type: `application/vnd.api+json`
* Pagination: `?page[number]=1&page[size]=20`
* Filtering: `?filter[field]=value`
* Sorting: `?sort=field` or `?sort=-field`
* Including related records: `?include=provider,findings`

ViewSets for tenant data inherit `BaseRLSViewSet`. Read, create, and update each have their own serializer. Business logic belongs in services and Celery tasks, not in serializers or views.

## Authentication and Access

Users belong to tenants through `Membership`. Permissions flow through `Role`, provider groups, and role assignments. Tenants can also authenticate with `TenantAPIKey` and with SAML (`SAMLConfiguration`). The UI uses NextAuth against the API.

## Attack Paths

After a completed AWS scan, the worker can build a graph that combines cloud inventory with findings. The long-lived sink is Neo4j by default (`ATTACK_PATHS_SINK_DATABASE=neo4j`). Amazon Neptune is an optional sink. Cartography ingestion still uses a temporary Neo4j database, so `NEO4J_*` settings stay required even when the sink is Neptune. Other providers are not ingested into Attack Paths yet.

## Where Code Lives

| Concern | Path |
| --- | --- |
| Checks, services, providers | `prowler/providers/` |
| Check runner, CLI, outputs | `prowler/lib/` |
| Compliance framework files | `prowler/compliance/` |
| Django project | `api/src/backend/` |
| Models | `api/src/backend/api/models.py` |
| JSON:API v1 | `api/src/backend/api/v1/` |
| Celery tasks | `api/src/backend/tasks/tasks.py` |
| Web app routes | `ui/app/(prowler)/` |
| Server actions | `ui/actions/` |
| MCP tools | `mcp_server/prowler_mcp_server/` |
| AI skills | `skills/` |
| Public docs | `docs/` |
