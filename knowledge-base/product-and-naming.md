# Product and Naming

Cloudsneeker is an independent product name for this repository. The software is a derivative work of [Prowler](https://github.com/prowler-cloud/prowler), licensed under the Apache License, Version 2.0. The license text is in [`LICENSE`](../LICENSE). Attribution and trademark limits are in [`NOTICE`](../NOTICE).

Keep `NOTICE`, `LICENSE`, and the original copyright notices with any distribution. The Apache License does not grant a right to use the Prowler name, logo, or trademarks. Cloudsneeker is not affiliated with, endorsed by, or sponsored by Prowler Cloud or the Prowler authors.

## What the Product Does

Cloudsneeker automates security and compliance assessments across cloud, identity, source-control, and infrastructure-as-code providers. A scan collects resources, runs built-in checks, and stores findings that the web application, reports, and compliance views can read.

The engine version in this tree is **5.45.0** (`pyproject.toml`, package name `prowler`).

## Two Names, One Repository

Everything a client can see uses **Cloudsneeker**: the web app, downloaded reports (CSV, OCSF JSON, HTML, SARIF, ASFF, compliance PDFs), API responses and the `/api/v1/docs` page, JWT issuer and audience, CLI output, Slack and Jira payloads, the MCP server, and help links. Package names, Python imports, Docker build paths, database identifiers, environment variables, and most internal symbols still use **prowler**.

Product identity is defined once per component and read everywhere else:

| Component | Brand module | Override |
| --- | --- | --- |
| SDK and CLI | `cloudsneeker/brand.py` (`Brand` dataclass, module-level `brand`) | `CLOUDSNEEKER_<FIELD>` environment variables via `load_brand()` |
| API and workers | `api/src/backend/cloudsneeker_api/brand.py` (re-exports the SDK brand, adds API helpers) | Same variables |
| Web app | `ui/cloudsneeker/brand.ts` (`BRAND`, `docsUrl()`, `checkDocsUrl()`) | Edit the file |
| MCP server | `mcp_server/prowler_mcp_server/cloudsneeker/brand.py` | `CLOUDSNEEKER_<FIELD>` variables |

Upstream files read those modules through one-line `cloudsneeker-hook` edits (listed in [Upstream Hooks](upstream-hooks.md)). Display copy inside upstream files is rewritten when a release is built, by `cloudsneeker/tools/rebrand.py` with `cloudsneeker/tools/rebrand.rules.toml`, so source stays identical to upstream. `cloudsneeker/tools/brand_audit.py` fails the build when an upstream name reaches a client-visible surface.

| Surface | Name to use | Where it lives |
| --- | --- | --- |
| Product, vendor, tagline, URLs | Cloudsneeker values | Brand modules above |
| In-app assistant | Seeker AI | `Brand.assistant_name`, `BRAND.assistantName` |
| Finding UIDs, ASFF ids, Jira labels, output file names | `cloudsneeker-...` | `Brand.finding_uid_prefix`, `jira_label_prefix`, `output_file_prefix` |
| CLI command | `cloudsneeker` (and `prowler`, kept for scripts) | `pyproject.toml` `[project.scripts]` |
| Python package and imports | `prowler` | `prowler/`, `import prowler` |
| PyPI / project metadata | `prowler` | `pyproject.toml` |
| Container user and paths | `prowler` | Docker entrypoints, `/home/prowler` |
| Environment variables | `PROWLER_*`, `DJANGO_*`, `UI_*` | compose files, `cloudsneeker/.env.example` |
| Database tables, JSON:API types, Celery tasks, Neo4j labels | upstream names | `api/` |
| UI route groups | `(prowler)` for inherited pages, `(cloudsneeker)` for new ones | `ui/app/` |
| Upstream documentation source | Prowler | `docs/` (not published); the product site is `cloudsneeker/docs/` |

Help links still use the `cloudsneeker.example` placeholders until a real domain is set. The mark is a cyan lens on a navy tile (the product looks for issues; Seeker AI is the assistant). Artwork lives in `ui/public/brand/`, `cloudsneeker/docs/logo/`, and `api/src/backend/tasks/assets/img/cloudsneeker_logo.png`.

## Product Surfaces in This Tree

This repository ships the open-source stack, not the hosted Prowler Cloud service.

| Surface | Role |
| --- | --- |
| CLI | Runs scans from a terminal through `prowler-cli.py` |
| Local Server | Self-hosted UI plus API, started with Docker Compose |
| SDK | Python engine that providers, services, and checks live in |
| MCP server | Model Context Protocol server that exposes the platform to AI clients |
| Local Dashboard | Optional Dash dashboard launched from the CLI |

Upstream product names such as Prowler Cloud, Prowler Hub, and Prowler Private Cloud appear in inherited source and in `docs/`. They are not Cloudsneeker product names. The build-time rules collapse tier names to the product name and `Brand.show_upsell` is `False`, so no screen advertises a hosted tier this product does not sell. Do not add new marketing copy that presents this tree as those products.
