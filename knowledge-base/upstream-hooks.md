# Upstream Hooks

A hook is the smallest edit inside an upstream Prowler file that connects Cloudsneeker code. New product behavior never lives in a hooked file; it lives in `cloudsneeker/`, `api/src/backend/cloudsneeker_api/`, `ui/cloudsneeker/`, `ui/app/(cloudsneeker)/`, or `mcp_server/prowler_mcp_server/cloudsneeker/`. When an upstream merge conflicts, keep the upstream side of the file and re-apply the hook described here.

Every hook carries the marker `cloudsneeker-hook` on its line (`# cloudsneeker-hook`, `// cloudsneeker-hook`). List the current set with:

```bash
rg -n "cloudsneeker-hook" --glob "!knowledge-base/**" --glob "!_data/**" .
```

Hooks come in three layers:

| Layer | What it is | Where the values live |
| --- | --- | --- |
| Brand modules | Frozen product identity: names, URLs, prefixes, feature flags | `cloudsneeker/brand.py` (`Brand`, `brand`, `load_brand`), `api/src/backend/cloudsneeker_api/brand.py`, `ui/cloudsneeker/brand.ts` (`BRAND`, `docsUrl`, `checkDocsUrl`), `mcp_server/prowler_mcp_server/cloudsneeker/brand.py` |
| Source hooks | One-line reads of a brand module inside an upstream file | Tables below |
| Transform rules | Build-time regex rewrites of display copy applied to a copy of the tree | `cloudsneeker/tools/rebrand.rules.toml`, run by `cloudsneeker/tools/rebrand.py` |

Display copy ("Prowler" inside a sentence, `hub.prowler.com` links, `prowler-output` file names in strings, the `ProwlerScan` role name) is handled by the transform rules so upstream files stay byte-identical. Structural changes (logos, URL catalogs, product IDs, finding UIDs, Security Hub product ARNs, disabled upsell) use source hooks because a regex cannot express them safely.

## SDK (`prowler/`, `pyproject.toml`, `Dockerfile`)

| File | Hook | Re-apply by |
| --- | --- | --- |
| `pyproject.toml` | `[project.scripts] cloudsneeker = "prowler.__main__:prowler"`; `cloudsneeker` in `tool.hatch.build.targets.sdist.include` and `.wheel.packages` | Keep the `prowler` script. Add the second script and the package in both hatch target lists. |
| `Dockerfile` | `COPY cloudsneeker/ /home/prowler/cloudsneeker/` after the `prowler/` and `dashboard/` copies | The brand package must exist in the image before `uv sync`. |
| `prowler/config/config.py` | `from cloudsneeker.brand import brand`; `html_logo_url = brand.website_url`; `square_logo_img = brand.logo_url`; `cloud_api_base_url` default `brand.api_url`; `check_current_version()` returns `brand.version_string(prowler_version)` and the upstream body is kept as `_upstream_check_current_version()` | No release lookup against upstream. Keep all other constants upstream. |
| `prowler/lib/banner.py` | `PRODUCT_NAME = brand.name` | Only the name line changes. |
| `prowler/lib/cli/parser.py` | `prog=brand.cli_command`; `--version` help `f"show {brand.name} version"`; `--push-to-cloud` help is `argparse.SUPPRESS` unless `brand.show_upsell` | Keep every other argument as upstream. |
| `prowler/lib/outputs/finding.py` | `from cloudsneeker.sdk import finding_uid`; `output_data["uid"] = finding_uid(...)` | UID prefix is `brand.finding_uid_prefix` (`cloudsneeker-`). |
| `prowler/lib/outputs/asff/asff.py` | imports from `cloudsneeker.sdk`; `Id=asff_finding_id(...)`, `ProductArn=security_hub_product_arn(...)`, `GeneratorId=asff_generator_id(...)`; `ProviderName = brand.security_hub_product_name` | Default ARN is the account-owned `product/<account>/default`; a partner ARN is used only when `security_hub_integration_name` is set. |
| `prowler/lib/outputs/csv/csv.py` | version column key is `brand.scanner_version_header` (`CLOUDSNEEKER_VERSION`) | Keep column order upstream. |
| `prowler/lib/outputs/html/html.py` | `from cloudsneeker.brand import brand`; `from cloudsneeker.sdk import html_title` | Title, logo link, and footer come from the brand. |
| `prowler/lib/outputs/jira/jira.py` | `FINDING_LABEL_PREFIX = f"{brand.jira_label_prefix}-finding"`; attempt label uses `brand.jira_label_prefix` | Labels become `cloudsneeker-finding-<uid>`. |
| `prowler/lib/outputs/ocsf/ocsf.py` | `ProductInfo(uid=brand.ocsf_product_uid, name=brand.name, vendor_name=brand.vendor)` | Three keyword lines. |
| `prowler/lib/outputs/sarif/sarif.py` | driver `name=brand.sarif_driver_name`, `informationUri=brand.website_url` | Two keys in the tool driver. |
| `prowler/lib/outputs/slack/slack.py` | `username=brand.slack_bot_name`; summary text `f"{brand.name} Scan Summary"`; `slack_title(...)`; `slack_footer_blocks()`; parameters line uses `brand.cli_command` | Footer links point at `brand.docs_url` and `brand.support_url`. |
| `prowler/lib/utils/vulnerability_references.py` | `PROWLER_HUB_CHECK_URL = brand.check_docs_url("{check_id}")` | Keep the constant name; only its value changes. |
| `prowler/providers/aws/lib/s3/s3.py` | connection test object uses `s3_test_object_body()` and `s3_test_object_key()` from `cloudsneeker.sdk` | Three call sites in the connection test. |
| `prowler/providers/aws/lib/security_hub/security_hub.py` | imports from `cloudsneeker.sdk`; `security_hub_subscription_arn(...)` check skipped for the default product; `**security_hub_product_filter(...)` when archiving | Default product needs no subscription check. |

Test-side hooks (SDK): `tests/conftest.py` applies `cloudsneeker.testing.UPSTREAM_COMPAT_ENV` before any `prowler` import so upstream suites still assert upstream names; `tests/config/config_test.py`, `tests/lib/outputs/html/html_test.py`, and `tests/lib/outputs/slack/slack_test.py` read the brand instead of literal strings. `tests/cloudsneeker/conftest.py` swaps the module-level `brand` back to the shipped defaults for Cloudsneeker's own tests; `tests/cloudsneeker/hooks_test.py` imports the hooked modules in a clean subprocess and proves they print the shipped names.

## API (`api/src/backend/`)

| File | Hook | Re-apply by |
| --- | --- | --- |
| `config/django/base.py` | `from cloudsneeker_api.brand import brand`; `"cloudsneeker_api"` appended to `INSTALLED_APPS`; `SPECTACULAR_SETTINGS["TITLE"] = f"API Reference - {brand.name}"`; `SIMPLE_JWT` issuer and audience default to `brand.jwt_default_issuer` | Keep upstream env-var names (`DJANGO_TOKEN_ISSUER`, `DJANGO_TOKEN_AUDIENCE`). |
| `config/urls.py` | `path("api/v1/", include("cloudsneeker_api.urls"))` after the upstream `api.v1.urls` include | Brand under `/api/v1/cloudsneeker/`; also mounts alerts, scan-configurations, and ingestions contracts the UI already calls. |
| `config/celery.py` | `autodiscover_tasks(["api", "cloudsneeker_api"])` | Loads Cloudsneeker ingestion and alert tasks. |
| `config/settings/social_login.py` | SAML `"entity_id": brand.saml_sp_entity_id` | `urn:cloudsneeker:sp`; must match `ui/cloudsneeker/brand.ts` `samlSpEntityId`. |
| `api/health.py` | `SERVICE_ID = health_service_id()`, `SERVICE_DESCRIPTION = health_description()` | `serviceId` is `cloudsneeker-api`. |
| `api/v1/views.py` | `spectacular_settings.TITLE = cloudsneeker_brand.api_title()` and `DESCRIPTION = api_description()` inside the schema view | The `/api/v1/docs` page and generated schema carry the product name. |
| `tasks/jobs/export.py` | output path prefix `brand.output_file_prefix` (two f-strings) | Report bundles are `cloudsneeker-output-<provider>-<timestamp>`. |
| `tasks/jobs/integrations.py` | `JIRA_LABEL_PREFIX = brand.jira_label_prefix` | Labels `cloudsneeker`, `cloudsneeker-<provider>`, ... |
| `tasks/jobs/reports/base.py` | `report_logo_path(...)`; PDF metadata `author=pdf_author()`, `creator=pdf_creator()`, `keywords=pdf_keywords(framework)`; footer `pdf_footer()` | Logo file is `tasks/assets/img/cloudsneeker_logo.png`. |
| `tasks/jobs/reports/cis.py`, `ens.py`, `nis2.py` | `prowler_logo_path = report_logo_path(...)`; `ens.py` footer `pdf_footer()` | Keep upstream variable names. |
| `tasks/jobs/reports/config.py` | `display_name=threatscore_display_name()` for the built-in risk framework | "Cloudsneeker ThreatScore". |
| `tasks/jobs/scan.py` | after a successful scan, enqueue `evaluate_alert_rules_task` | Alerts stay Cloudsneeker-only; failures are logged and ignored. |

Test-side hooks (API): `api/tests/test_views.py`, `tasks/tests/test_integrations.py`, and `tasks/tests/test_reports_base.py` assert against `cloudsneeker_api.brand` values. `cloudsneeker_api/tests/` covers the brand helpers, the app registration, `/api/v1/cloudsneeker/brand`, and the OpenAPI entry.

## UI (`ui/`)

| File | Hook | Re-apply by |
| --- | --- | --- |
| `config/site.ts` | `siteConfig.name` and `description` read `BRAND` | Comment line marks the file; no literal name. |
| `components/icons/prowler/ProwlerIcons.tsx` | `ProwlerExtended`/`ProwlerShort` render the artwork from `ui/cloudsneeker/brand-logo.tsx` | Keep the component names; they are imported across the app. |
| `components/auth/oss/auth-layout.tsx` | re-exports the responsive split-screen experience from `ui/cloudsneeker/auth-layout.tsx` | Form children and submission behavior remain inherited. |
| `components/compliance/threatscore-logo.tsx` | re-exports product artwork from `ui/cloudsneeker/threatscore-logo.tsx` | Prevents inherited vendor artwork from appearing on the overview. |
| `components/layout/app-sidebar/navigation-config.ts` | imports `BRAND`, `docsUrl`, `withCloudsneekerNavigation`; `apiReferenceUrl = apiDocsUrl`; Documentation `docsUrl()`, Support `BRAND.supportUrl`, Check Catalog `docsUrl("checks")`; final `filterNavigationByPermissions(withCloudsneekerNavigation(sections, pathname), permissions)` | `withCloudsneekerNavigation` drops HELP and turns built-in cloud features into real links. |
| `app/(prowler)/alerts/page.tsx` | also allows `isCloudsneekerFeatureEnabled("alerts")` | Opens Alerts without `UI_CLOUD_ENABLED`. |
| `app/(prowler)/findings/_components/findings-filters-section.tsx` | `isCloudEnabled={isCloud() \|\| isCloudsneekerFeatureEnabled("alerts")}` | Seed-from-findings works without cloud. |
| `app/(prowler)/scans/config/page.tsx` | also allows `isCloudsneekerFeatureEnabled("scanConfiguration")` | Opens Scan profiles without cloud. |
| `app/api/ingestions/route.ts`, `[ingestionId]/route.ts` | also allow `isCloudsneekerFeatureEnabled("cliImport")` | CLI Import proxy works without cloud. |
| `components/scans/scans-page-shell.tsx` | CLI Import banner/modal when feature enabled | Uses `manage_scans` via Cloudsneeker permission mapping. |
| `actions/auth/auth.ts` | `withCloudsneekerPermissions(...)` on `/users/me` permissions | Maps `manage_scans` onto alerts/ingestions keys. |
| `components/layout/app-sidebar/app-sidebar-content.tsx` | `aria-label={`${BRAND.name} home`}`; upsell block gated by `BRAND.showUpsell` | — |
| `components/layout/app-sidebar/sidebar-footer.tsx` | footer links read `BRAND` | — |
| `components/auth/oss/sign-up-form.tsx` | terms link `href={BRAND.termsUrl}` | — |
| `components/integrations/saml/saml-config-form.tsx` | SP entity ID `value={BRAND.samlSpEntityId}` | — |
| `components/findings/table/finding-triage-cells.tsx` | `CLOUD_ONLY_TOOLTIP_COPY = BRAND.unavailableFeatureCopy` | — |
| `components/shadcn/badge/badge.tsx` | `variant === "cloud"` renders nothing unless `BRAND.showUpsell` | — |
| `components/survey/runtime-feedback-survey.tsx` | `SURVEY_NAME = BRAND.surveyName` | — |
| `app/(prowler)/compliance/_components/cross-provider-hub-link.tsx` | `href={docsUrl(`compliance/${id}`)}` | Resolves to the generated framework page in `cloudsneeker/docs`. |
| `app/api/health/route.ts` | `serviceId: BRAND.serviceId` | `cloudsneeker-ui`. |
| `lib/external-urls.ts` | `PROWLER_HUB_URL = BRAND.docsUrl`; `PROWLER_CF_TEMPLATE_URL = BRAND.cloudformationTemplateUrl`; `BILLING_URL`; `DOCS_URLS` built with `docsUrl()` | Keep upstream export names. |
| `lib/cloud-upgrade.ts` | `CLOUD_SIGN_UP_URL = BRAND.websiteUrl`; `PRICING_URL = BRAND.pricingUrl || BRAND.websiteUrl` | — |
| `lib/deployment.ts` | `PROWLER_CLOUD_ONLY_TOOLTIP = BRAND.unavailableFeatureCopy` | Keep the export name. |
| `lib/vulnerability-references.ts` | `HUB` label `View in ${BRAND.name} documentation`; hostname match against the brand docs host | — |
| `lib/lighthouse-v1/system-prompt.ts` | `brandSystemPrompt` from `ui/cloudsneeker/lighthouse-prompt.ts` replaces the product paragraph | The agent speaks as the product and cites product docs. |
| `store/cloud-upgrade/store.ts` | upsell modal opens only when `BRAND.showUpsell` | — |
| `types/findings-triage.ts` | `FINDING_TRIAGE_BILLING_HREF = BRAND.pricingUrl` | — |

Test-side hooks (UI): `vitest.setup.ts` mocks `@/cloudsneeker/brand` with `showUpsell: true` so upstream upsell suites run unchanged; about twenty `*.test.ts(x)` files read `BRAND` instead of a literal (`navigation-config.test.ts` expects the HELP section to be absent). Two browser suites, `providers-page.integration.test.tsx` and `slack-page.integration.test.tsx`, compare documentation links against `DOCS_URLS` instead of upstream slugs. Run `rg -n "cloudsneeker-hook" ui --glob "*.test.*"` for the list.

In-app documentation paths (`user-guide/providers/aws`, `user-guide/tutorials/app-slack-integration`, ...) are kept as upstream wrote them; `cloudsneeker/docs/docs.json` `redirects` map every one of them to a product page. `tests/cloudsneeker/docs_links_test.py` fails when the UI links to a path the site does not serve.

### Legacy copy edits

These upstream UI files were edited for product copy before the transform rules existed. Do not add more copy to them. On a conflicting merge, take the upstream file; the `display-name` transform rule supplies the product name at build time. Re-apply the behavior changes only if the feature still needs them.

* `app/(prowler)/_overview/_components/overview-banner.tsx` (and test): agents banner links to the in-app Lighthouse chat instead of the hosted-tier docs.
* `app/(prowler)/page.tsx`: banner wiring for the above.
* `components/auth/oss/sign-in-form.tsx` with `lib/auth-callback-url.ts` (`resolvePostLoginPath`): skips the Cloud-only email-verification redirect when `isCloud()` is false.
* `components/providers/wizard/wizard-stepper.tsx`, `components/registry/registry-artifact-card.tsx`: product name in step copy and an `aria-label`.

## MCP server (`mcp_server/prowler_mcp_server/`)

| File | Hook | Re-apply by |
| --- | --- | --- |
| `server.py` | `from prowler_mcp_server.cloudsneeker.brand import brand`; `FastMCP(name=brand.server_name)`; `setup_main_server(server=None)` mounts onto a caller's server; Hub tools behind `brand.mcp_hub_tools`, docs tools behind `brand.mcp_docs_tools` (both off); health `serviceId`/`description` from brand | Hub and docs tools stay disabled: they would call upstream hosts. |
| `main.py` | argparse `description=brand.description` | — |
| `lib/logger.py` | `get_logger(brand.server_name)` | — |
| `prowler_app/server.py` | `FastMCP(brand.app_server_name, ...)` | — |
| `prowler_app/utils/api_client.py` | `User-Agent: f"{brand.server_name}/{__version__}"` | — |
| `prowler_app/utils/auth.py` | `API_BASE_URL` default `brand.api_base_url`; `User-Agent` as above | Keep the upstream env-var names. |

Test-side hook (MCP): `mcp_server/tests/conftest.py` applies the compat env before importing the server.

## Transform rules (`cloudsneeker/tools/rebrand.rules.toml`)

Rules run at build time against a copy of the tree (`cloudsneeker/deploy/docker/source.Dockerfile`, `cloudsneeker/deploy/scripts/build.*`). Source files stay upstream-identical. `python cloudsneeker/tools/rebrand.py --check` fails when a non-optional rule no longer matches anything; fix or retire the rule, then update `tests/cloudsneeker/tools/rebrand_test.py::test_check_passes_on_full_tree`.

| Rule id | Replaces | Scope |
| --- | --- | --- |
| `prowler-cloud-tier`, `prowler-pro-compact` | "Prowler Cloud" / "Prowler Pro" tier names → product name | application text |
| `prowler-hub`, `hub-check-url`, `hub-root-url`, `docs-url`, `github-repo-url`, `other-prowler-hosts` | upstream hosts and Hub links → `docs_url`, `check_docs_url`, `website_url` | application text |
| `prowler-slack-handle` | upstream Slack community link → `support_url` | application text |
| `display-name` | `\bProwler\b` → `name` | application text, compliance JSON, check metadata |
| `output-file-prefix`, `inventory-file-prefix` | `prowler-output`, `prowler-inventory` → brand prefixes | application text |
| `aws-scan-role-name`, `aws-scan-role-connection-test-file`, `cloudformation-template-*` | `ProwlerScan` role, template contact and text | UI, `permissions/templates/**` |
| `asff-product-field-names` | `ProwlerResourceName` → `CloudsneekerResourceName` | `prowler/lib/outputs/asff/asff.py` |
| `mcp-app-namespace`, `mcp-tool-prefix` | MCP namespace and tool prefix → `slug` | `mcp_server/**` |

Excluded on purpose: `NOTICE`, `LICENSE`, changelogs, lockfiles, tests, migrations, `docs/` (upstream Mintlify site), `cloudsneeker/testing.py`.

## Gates

CI: `.github/workflows/cloudsneeker-release.yml` and `.github/workflows/cloudsneeker-images.yml`.

* `source-gate`: `rebrand.py --check` (no stale rules) and `brand_audit.py --source` (Cloudsneeker-owned directories contain no upstream names).
* `docs-gate`: `gen_check_docs.py` then `brand_audit.py --tree cloudsneeker/docs`.
* `build-gate`: export the transformed tree, `brand_audit.py --tree build/tree`, generate samples with `cloudsneeker/tools/sample_outputs.py`, `brand_audit.py --artifacts build/artifacts`.
* `images`: build the component images from the transformed tree and audit a real CLI run's output directory.

## Adding a Hook

1. Exhaust an extension point first: `cloudsneeker/`, `api/src/backend/cloudsneeker_api/` (new route in `urls.py`), `ui/cloudsneeker/navigation.ts`, `ui/app/(cloudsneeker)/`.
2. If the change is display copy, add or widen a rule in `rebrand.rules.toml` and extend the rebrand fixture test. Do not edit the upstream file.
3. If registration is still required, add a new field to the brand module when a value is needed, make the smallest edit, and put `cloudsneeker-hook` on that line.
4. Add a row to the matching table above with the file, the hook, and how to re-apply it after a merge.
5. Cover it: a Cloudsneeker test asserts the shipped value; if an upstream test asserted the old literal, make it read the brand and mark that line too.
