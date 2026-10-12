# Cloudsneeker deployment

Install artifacts for the product. Everything here is Cloudsneeker-owned; the
upstream `docker-compose*.yml`, `Dockerfile`s, and `contrib/k8s` are left as
they are so upstream merges stay clean.

## How a release is built

Source stays byte-identical to upstream apart from the `cloudsneeker-hook`
lines. The long tail of display copy (help text, hub links, output file
prefixes, MCP tool names) is rewritten at build time:

1. `docker/source.Dockerfile` copies the repository, runs
   `cloudsneeker/tools/rebrand.py --apply`, and builds the SDK wheel. The two
   stages are exported with `docker build --output` into `build/tree` and
   `build/wheels`.
2. `cloudsneeker/tools/brand_audit.py --tree build/tree` must report zero
   hits, and so must `--artifacts` over a sample scan output generated from
   the rebranded tree (`cloudsneeker/tools/sample_outputs.py`).
3. The component images are built **from `build/tree` with the upstream
   Dockerfiles**: `build/tree` (CLI), `build/tree/api`, `build/tree/ui`,
   `build/tree/mcp_server`.
4. The API image gets one extra layer (`docker/api.Dockerfile`) that replaces
   the SDK the upstream Dockerfile installed from `prowler-cloud/prowler@master`
   with the wheel from step 1, which carries the brand hooks and the
   `cloudsneeker` package.

`scripts/build.sh` (Linux/macOS/CI) and `scripts/build.ps1` (Windows) run
these steps end to end:

```bash
cloudsneeker/deploy/scripts/build.sh v1.0.0
REGISTRY=ghcr.io/acme PUSH=1 cloudsneeker/deploy/scripts/build.sh v1.0.0
```

```powershell
pwsh cloudsneeker/deploy/scripts/build.ps1 -Tag v1.0.0 -Registry ghcr.io/acme -Push
```

Images: `<registry>/cli`, `<registry>/api`, `<registry>/ui`, `<registry>/mcp`.
The CI version of the same pipeline is `.github/workflows/cloudsneeker-release.yml`;
it blocks on any brand-audit hit and pushes only on `cloudsneeker-v*` tags.

## Docker Compose

```bash
cd cloudsneeker/deploy
cp ../.env.example .env        # fill in every placeholder; .env is gitignored here
docker compose up -d
```

Services: `cloudsneeker-api`, `cloudsneeker-worker`, `cloudsneeker-worker-beat`,
`cloudsneeker-ui`, `cloudsneeker-mcp`, plus `postgres`, `valkey`, and `neo4j`.
Set `CLOUDSNEEKER_REGISTRY` and `CLOUDSNEEKER_*_VERSION` in `.env` to pick
the images.

## Helm

`helm/cloudsneeker-app` deploys the application tier (API, workers, beat, web
app, MCP server) and an Ingress for three hosts. PostgreSQL, Valkey, and Neo4j
are external; point `datastores.*` at them.

```bash
helm upgrade --install cloudsneeker cloudsneeker/deploy/helm/cloudsneeker-app \
  --namespace cloudsneeker --create-namespace \
  --set hosts.app=app.example.com,hosts.api=api.example.com,hosts.mcp=mcp.example.com \
  --set existingSecret=cloudsneeker-secrets
```

Create `cloudsneeker-secrets` beforehand with the keys listed under `secrets`
in `values.yaml`. Passing secrets through `--set` is for development only.

## Brand configuration

Names, URLs, and identifiers come from the brand modules
(`cloudsneeker/brand.py`, `api/src/backend/cloudsneeker_api/brand.py`,
`ui/cloudsneeker/brand.ts`, `mcp_server/prowler_mcp_server/cloudsneeker/brand.py`).
URLs can be overridden at runtime with `CLOUDSNEEKER_*` environment variables
(see `../.env.example`). The MCP server ships with the upstream Hub and
Documentation tool sets disabled; set `CLOUDSNEEKER_MCP_HUB_TOOLS=true` /
`CLOUDSNEEKER_MCP_DOCS_TOOLS=true` to mount them.
