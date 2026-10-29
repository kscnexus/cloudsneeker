# Third-Party Notices

Cloudsneeker ships the programs below inside its service images. Each keeps
its own license. Cloudsneeker runs them as separate, unmodified programs
(command-line tools or a network service) and does not link them into its
own code. Python and JavaScript libraries installed from `api/uv.lock`,
`uv.lock`, `mcp_server/uv.lock` and `ui/pnpm-lock.yaml` keep the licenses
declared in their package metadata.

| Component | Version | License | Where it is used | Source |
| --- | --- | --- | --- | --- |
| Prowler | as merged into this repository | Apache-2.0 | Base of the SDK, API, UI and MCP server | https://github.com/prowler-cloud/prowler |
| Trivy | 0.74.0 (`api/Dockerfile`, `TRIVY_VERSION`) | Apache-2.0 | Application Security scans (dependencies, containers, IaC, secrets, SBOM, Kubernetes) | https://github.com/aquasecurity/trivy |
| Cloud Custodian (`c7n`, `c7n-azure`, `c7n-gcp`, `c7n-kube`) | 0.9.53 / 0.7.52 / 0.4.52 / 0.2.52 (`cloudsneeker/deploy/docker/api.Dockerfile`) | Apache-2.0 | Cloud Governance dry-runs, in a separate virtual environment at `/opt/c7n` | https://github.com/cloud-custodian/cloud-custodian |
| OpenGrep | 1.30.2 (`OPENGREP_VERSION`) | LGPL-2.1 | Static analysis (SAST) engine, the unmodified release binary at `/opt/opengrep/opengrep` | https://github.com/opengrep/opengrep |
| GitLab sast-rules | v2.10.1 (`SAST_RULES_REF`), folders `csharp go java javascript python scala` | MIT (some `go/` rules are Apache-2.0 gosec ports) | SAST rule packs at `/opt/opengrep/rules` | https://gitlab.com/gitlab-org/security-products/sast-rules |
| Cartography | 0.138.1 (`api/pyproject.toml`) | Apache-2.0 | Attack Paths graph ingestion | https://github.com/cartography-cncf/cartography |
| DozerDB (Neo4j Community Edition with DozerDB plugins) | `graphstack/dozerdb:5.26.27.0` (`.github/workflows/cloudsneeker-images.yml`, `NEO4J_IMAGE`) | GPL-3.0 | Graph database for Attack Paths, run as its own service | https://github.com/DozerDB/dozerdb-core , https://github.com/neo4j/neo4j |

## Obligations to keep

- **OpenGrep (LGPL-2.1):** ship the binary unmodified, keep its license
  text available, and point recipients to the corresponding source at the
  exact release tag. Replacing the binary must stay possible (it is a
  separate file selected by `OPENGREP_BIN`).
- **DozerDB / Neo4j Community (GPL-3.0):** the database runs as a separate
  network service and is not linked with Cloudsneeker code. When the image is
  distributed to a customer (for example a deployment in the customer's AWS
  account), provide the GPL-3.0 text and the source location of the exact
  image version.
- **Apache-2.0 components:** keep their LICENSE and NOTICE files in the
  images. Do not use their names or logos as product branding.
- **Rule packs:** do not add Semgrep registry rules (Semgrep Rules License)
  or `opengrep/opengrep-rules` (LGPL-2.1 with the Commons Clause). Check the
  license of every file before adding a new rule pack.

## Updating this file

Change the version here whenever the matching build argument or image
reference changes. Review new transitive licenses with the lockfiles before
a release.
