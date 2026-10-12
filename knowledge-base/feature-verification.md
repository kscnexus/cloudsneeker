# Feature Verification

Every feature ships with unit tests, a compatibility check against the features it can affect, and a pass of the integrations that consume the same data. The gate is in `.cursor/rules/feature-verification.mdc`.

## Unit Tests

Write the failing test first (`skills/tdd/SKILL.md`). Cover success, failure, and the empty or unauthorized case. Match the runner already used in that tree.

| Area | File pattern | Run |
| --- | --- | --- |
| SDK | `tests/**/<name>_test.py` | `uv run pytest tests/<path> -v` |
| API | `api/src/backend/**/tests/test_*.py` | `cd api && uv run pytest <path> -v` |
| UI | `*.test.ts` or `*.test.tsx` next to the source | `cd ui && pnpm test:unit <path>` |
| MCP | `mcp_server/tests/` | `cd mcp_server && uv run pytest <path> -v` |

A changed function without a test for its new behavior is not done. Do not remove or loosen an existing assertion to get a green run.

## Compatibility

After the new tests pass, run the unit suite for that component. Then run the suites for shared behavior the change can reach:

* Auth, users, and roles
* Providers and `ProviderSecret`
* Scans and findings
* Mute rules and report output

Those suites protect the other features. A failure there is a break in the feature you just added, even when the new tests pass.

## Integrations

These product integrations read providers, credentials, scans, or findings. A feature that touches any of those must pass the existing tests for all four:

* Amazon S3
* AWS Security Hub
* Jira
* Slack

```bash
cd api && uv run pytest src/backend/tasks/tests/test_integrations.py -q
```

When the UI changed, also run:

```bash
cd ui && pnpm test:integration
```

Sign-in or secret changes also run the SAML and API-key tests. Changes to sign-in, providers, invitations, or scans also run `cd ui && pnpm test:e2e`.

Tests mock the outside service. They do not use live Jira, Slack, AWS, or S3 credentials.

## Brand Gate

Any change that adds client-visible text, a URL, a file name, or an identifier also runs:

```bash
python cloudsneeker/tools/rebrand.py --check          # no stale transform rule
python cloudsneeker/tools/brand_audit.py --source     # Cloudsneeker directories carry no upstream name
uv run pytest tests/cloudsneeker -q                   # brand, hooks, tools, sample outputs
```

Upstream test suites run with the upstream-compatible brand (`cloudsneeker.testing.UPSTREAM_COMPAT_ENV`, `mcp_server/tests/conftest.py`, `ui/vitest.setup.ts`) so they stay byte-identical to upstream. Cloudsneeker's own suites (`tests/cloudsneeker/`, `api/src/backend/cloudsneeker_api/tests/`, `ui/cloudsneeker/`, `ui/app/(cloudsneeker)/`) assert the shipped values.

### Windows

The API and MCP suites import Unix-only modules (`resource`, `fcntl`, `socket.socketpair`). On Windows, put stand-ins on `PYTHONPATH` from a directory outside the repository, or run those suites in WSL or Docker. A few SDK and API tests also fail only on Windows (temp-file permissions, `cp1252` decoding, `chmod`); they are not brand regressions.
