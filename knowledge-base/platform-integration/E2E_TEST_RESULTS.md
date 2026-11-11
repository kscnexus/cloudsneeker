# E2E Test Results

## Local (Windows development machine, 2026-11-11)

The machine has no test database and no Docker, so database tests and async MCP tests run in CI only ([Local test environment notes](../local-development.md)).

| Suite | Command | Result |
| --- | --- | --- |
| API, no database: alerts, conditions, report catalogue | `pytest --noconftest` with stand-in `fcntl`/`resource` | 69 passed |
| API, mute and governance (no-database parts) | same | passed |
| API imports, routes, `makemigrations --check` | Django setup script | No missing migrations; `area-findings/mute` resolves |
| MCP tool registration | import the root server, list tools | 54 tools, the five new ones present |
| UI unit: cloudsneeker, (cloudsneeker) pages, alerts, compliance, mutelist, Seeker AI, compliance components | `vitest run ...` | 1098 passed, 3 failed: `shared-reports/[token]/page.test.tsx` timeouts at 5 s, a known cold-run flake on this machine, unrelated |
| UI type-check | `tsc --noEmit` | Clean |
| Brand audit | `brand_audit.py --source` | 0 hits |

## CI

| Run | Result |
| --- | --- |
| Pull request: "Cloudsneeker: Tests" (SDK, API with database, UI, MCP) | Pending at time of writing; see the pull request |

## Deployed Site Scenarios

To run on https://cloudsneeker.vercel.app once deployed. Status is recorded here as each runs.

| Scenario | Steps | Status |
| --- | --- | --- |
| Compliance | Sidebar Compliance → Single Scan; Provider lists cloud then SaaS, no code or image providers; Account narrows the scan list; frameworks match the provider | Pending deploy |
| Alerts | `/alerts` → New alert → Modules = Application Security → Test shows only application counts; rule list shows the module | Pending deploy |
| Application Security alert | Rescan a target with an Application Security rule enabled; notification links to the scan run | Needs a confirmed recipient or Slack channel on the tenant |
| Governance alert | Run a policy dry run with a governance rule enabled | Needs a confirmed recipient or Slack channel |
| Mute | Mute an application finding with a reason; it leaves the workspace, the detail shows the rule; it appears on the Mutelist page | Pending deploy |
| Governance mute | Mute a governance finding from `/governance/findings`; it leaves the list | Pending deploy |
| Governance lists | Policies and Reports tabs: search, account, status, paging | Pending deploy |
| Targets list | Search, target type, paging over the tenant's 318 targets | Pending deploy |
| Seeker AI | The questions in [Seeker AI Cross-Module Audit](SEEKER_AI_CROSS_MODULE_AUDIT.md) | Needs a working model key on the tenant (credits were exhausted on 2026-10-29) |
| RBAC | Read-only role sees governance policies of its provider groups only | Needs a second user; not created on the public site (security rule) |
