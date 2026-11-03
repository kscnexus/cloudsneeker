# Governance Policy Library and AI Drafting

Cloud Governance ships a built-in library of dry-run policies for AWS, Azure and Google Cloud, and a Seeker AI option that drafts a policy from a plain-language request. Both create ordinary governance policies (`CustodianPolicy` rows), so scheduling, dry-runs, reports and findings work the same as for hand-written policies.

## Library data

The library is data, not code: `api/src/backend/cloudsneeker_api/services/custodian_library/{aws,azure,gcp}.yaml`. Each entry has:

| Field | Meaning |
| --- | --- |
| `id` | Stable key, prefixed by the cloud (`aws-s3-public`). It is also the policy `name` inside the rendered YAML, which is how coverage finds library policies in a workspace |
| `name`, `description` | Catalogue text shown in the UI |
| `category` | One of the keys of `LIBRARY_CATEGORIES` in `services/custodian_library.py` |
| `severity` | `critical`, `high`, `medium` or `low` |
| `frameworks` | Tags such as `CIS`, `NIST 800-53`, `PCI DSS`, `SOC 2`, `HIPAA`, `FinOps`. They are search tags, not control-by-control mappings |
| `starter` | Part of the recommended starter pack for that cloud |
| `resource`, `filters` | The policy body. Entries never declare `actions` |

Policy content is written for Cloudsneeker. Do not copy policies from GPL-licensed policy collections or builders; take ideas only.

Rules for new entries:

- Keep 50 to 100 entries per cloud and at least one entry per category; `tests/test_custodian_library.py` enforces both.
- Use only filter types that exist for the resource in the pinned engine version (`C7N_*` build arguments in `cloudsneeker/deploy/docker/api.Dockerfile`). Prefer `type: value` on documented API attributes.
- Before committing, render every entry and run the engine's validator against the pinned version. CI does not install the engine, so the unit tests only check structure:

```bash
# in a scratch virtualenv with c7n==<C7N_VERSION> c7n-azure==<...> c7n-gcp==<...>
python -c "import yaml,sys; sys.path.insert(0,'api/src/backend'); from cloudsneeker_api.services.custodian_library import list_library_policies as l; print(yaml.safe_dump({'policies':[yaml.safe_load(e['policy_yaml'])['policies'][0] for e in l(provider_type='aws')]}))" > lib-aws.yml
custodian validate lib-aws.yml
```

## API

`CustodianLibraryViewSet` in `views_custodian_library.py`, registered at `/api/v1/custodian-library` (permission `MANAGE_SCANS`, documents built by hand):

| Method and path | Purpose |
| --- | --- |
| `GET /custodian-library?provider_type=&category=&search=&starter=true` | Library entries with `installed` per entry; `meta.categories` and `meta.coverage` (per cloud and category: `total`, `active`) |
| `POST /custodian-library/install` `{provider_id, policy_ids[]}` | Creates one dry-run policy per entry. Entries already on that provider are skipped; a name taken by another provider gets the provider alias as a suffix |
| `POST /custodian-library/generate` `{provider_type, prompt, resource_type?}` | Seeker AI draft, see below |
| `POST /custodian-library/validate` `{provider_type, policy_yaml}` | The same checks a saved policy goes through: structure, no actions, resource prefix, engine validator |

## Seeker AI drafting

`services/custodian_ai.py` reuses the tenant's Seeker AI configuration: the default provider and model from `LighthouseTenantConfiguration`, falling back to the first active `LighthouseProviderConfiguration` and its first model. OpenAI, OpenAI-compatible (including Claude through the Anthropic compatibility layer) and Bedrock are supported through the upstream helpers in `tasks/jobs/lighthouse_providers.py`.

The prompt includes two library policies for the chosen cloud as examples. The reply's YAML is normalized (first policy only, `actions`/`mode`/`notify` removed, name slugged) and validated. A failed validation goes back to the model once with the error; the draft is returned either way, with `valid` and `validation_error`, so the user can fix it by hand. The UI only enables Save after the current YAML passed a check, and saving goes through the normal create endpoint, which validates again.

Errors: no Seeker AI provider or model returns 400 with code `llm_not_configured`; a provider failure (for example exhausted OpenAI credits) returns 424 with code `llm_error`, so the UI shows the message instead of a generic server error.

## UI

- `/governance/library?provider=aws|azure|gcp`: coverage cards per category (click to filter), search, category and severity filters, starter-pack-only and hide-added toggles, YAML preview, one-click Add per policy, and Add starter pack. Components: `cloudsneeker/components/custodian-library-browser.tsx`, helpers in `cloudsneeker/lib/custodian-library.ts`.
- `/governance/generate`: prompt, cloud and optional resource type; review and edit the draft, re-check, then save. Component: `cloudsneeker/components/custodian-policy-generator.tsx`. The page sets `maxDuration = 60` because drafting waits on the LLM.
- The Cloud Governance page header and the empty state link to both.
