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
| `prowler/providers/iac/iac_provider.py` | `from cloudsneeker.git_auth import (authenticated_clone_url, iac_clone_url, redact, redact_exception)`; `__init__` and `test_connection` take `username: str = None`; `self.git_username = username`; `_clone_repository` builds the URL with `iac_clone_url(repository_url, github_username, personal_access_token, oauth_app_token, getattr(self, "git_username", None))` and its `except` starts with `error = redact_exception(error, personal_access_token, oauth_app_token)`; `test_connection` uses `auth_url = authenticated_clone_url(scan_repository_url, oauth_app_token, username)` and `error_msg = redact(str(e), oauth_app_token)`; unused `import re` removed | Replace upstream's github.com-only `replace()` block in `_clone_repository` and the `x-access-token` regex block in `test_connection` with the single helper calls, so the clone and the connection test build the same per-host URL (GitHub `x-access-token`, GitLab `oauth2`, Bitbucket `x-token-auth` or `<username>`, Azure DevOps `pat`; table in `cloudsneeker/git_auth.py`). Tokens never appear in logs or errors. |

Test-side hooks (SDK): `tests/conftest.py` applies `cloudsneeker.testing.UPSTREAM_COMPAT_ENV` before any `prowler` import so upstream suites still assert upstream names; `tests/config/config_test.py`, `tests/lib/outputs/html/html_test.py`, and `tests/lib/outputs/slack/slack_test.py` read the brand instead of literal strings. `tests/cloudsneeker/conftest.py` swaps the module-level `brand` back to the shipped defaults for Cloudsneeker's own tests; `tests/cloudsneeker/hooks_test.py` imports the hooked modules in a clean subprocess and proves they print the shipped names. `tests/providers/iac/iac_provider_test.py::test_clone_repository_with_oauth` expects `x-access-token:` instead of `oauth2:` for github.com (marked line); `tests/cloudsneeker/git_auth_test.py` covers the helper and both IaC hooks.

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
| `api/rbac/permissions.py` | `TASK_REVOKE_PERMISSIONS.update(cloudsneeker_task_revoke_permissions(Permissions))` after the upstream map | Every Cloudsneeker `RLSTask` needs an entry (`cloudsneeker_api/task_permissions.py`); `test_every_rls_task_has_revoke_permissions` enforces it. |
| `tasks/jobs/scan.py` | after a successful scan, enqueue `evaluate_alert_rules_task` | Alerts stay Cloudsneeker-only; failures are logged and ignored. |
| `tasks/tasks.py` | `perform_scheduled_scan_task` gets `(next, current)` from `scheduled_scan_window(...)`; `_get_or_create_next_scheduled_scan` steps with `advance_past_now(...)`; import trimmed to `from datetime import datetime` | Cloudsneeker DAILY/WEEKLY/MONTHLY schedules are crontabs (`cloudsneeker_api/services/scan_schedule.py`); upstream math assumes an interval and crashed with `'NoneType' object has no attribute 'period'`. Interval tasks keep upstream math. |
| `tasks/jobs/lighthouse_providers.py` | `_list_openai_compatible_models` passes `openai_compatible_client_kwargs(...)` to `openai.OpenAI` and `openai_compatible_models_list_kwargs(...)` to `models.list` (`cloudsneeker_api/llm_compat.py`) | Claude works as an "OpenAI Compatible" Seeker AI provider: Anthropic's `/v1/models` needs `x-api-key` + `anthropic-version` and pages 20 at a time. No-op for other base URLs. |
| `api/v1/serializers.py` | `ImageProviderSecret` gains optional `image_filter` / `tag_filter` and calls `validate_image_filter_patterns(attrs)` (`cloudsneeker_api/image_filters.py`) | The provider form collects both; upstream dropped them, so a registry scan covered every repository. |
| `api/v1/serializers.py` | `from cloudsneeker_api.ecr_auth import ECR_ROLE_ARN_REGEX`; `IacProviderSecret.username` (optional, blank allowed); `ImageProviderSecret` gains optional `ecr_role_arn` (`RegexField(ECR_ROLE_ARN_REGEX)`), `ecr_external_id`, and `registry_insecure` (`BooleanField`, default `False`) | One field line each. Bitbucket app passwords and Bitbucket Server / Azure DevOps tokens need a username; ECR role fields feed `cloudsneeker_api/ecr_auth.py`. |
| `api/utils.py` | `from cloudsneeker_api.ecr_auth import apply_ecr_auth, ecr_connection_kwargs`; `get_prowler_provider_kwargs` IaC branch passes `username` when the secret has one, image branch starts with `prowler_provider_kwargs = apply_ecr_auth(provider.uid, prowler_provider_kwargs)`; `prowler_provider_connection_test` IaC branch passes `username`, image branch starts with `ecr_failure, prowler_provider_kwargs = ecr_connection_kwargs(...)` and returns `ecr_failure` when set | ECR tokens expire after 12 hours, so the worker mints one per scan / connection test (`ecr:GetAuthorizationToken`, optional `sts:AssumeRole` with `ExternalId`) when the uid is an ECR host and no static registry credentials are stored. `ecr_role_arn` / `ecr_external_id` are stripped before `ImageProvider`. |
| `Dockerfile` | `RUN chmod +x ./docker-entrypoint.sh` after the entrypoint copy | The exported build tree does not keep the executable bit. | |

Test-side hooks (API): `conftest.py` imports the autouse fixture `cloudsneeker_api.testing.upstream_compat_brand`, which swaps `cloudsneeker_api.brand.brand` for `cloudsneeker.testing.UPSTREAM_COMPAT_ENV` values in every test outside `cloudsneeker_api/` (so `test_reports_ens.py` still finds "Prowler" in the PDF footer). `.github/workflows/cloudsneeker-tests.yml` deselects `TestScheduleViewSet::test_schedule_invalid_method_list[get]`: the Cloudsneeker `ScheduleViewSet` serves `GET /schedules` on purpose, so the upstream OSS 405 expectation cannot hold. `api/tests/test_views.py`, `tasks/tests/test_integrations.py`, and `tasks/tests/test_reports_base.py` assert against `cloudsneeker_api.brand` values. `cloudsneeker_api/tests/` covers the brand helpers, the app registration, `/api/v1/cloudsneeker/brand`, and the OpenAPI entry.

## UI (`ui/`)

| File | Hook | Re-apply by |
| --- | --- | --- |
| `config/site.ts` | `siteConfig.name` and `description` read `BRAND` | Comment line marks the file; no literal name. |
| `app/(prowler)/page.tsx` | `import { RiskOverview } from "@/cloudsneeker/components/risk-overview"; // cloudsneeker-hook` and `{/* cloudsneeker-hook: one risk view across every product area */}` + `<RiskOverview />` after `<OverviewProviderContext />` | Overview risk view (score, severity totals, areas, top risks, trend) from the latest completed executive report run (`ui/cloudsneeker/components/risk-overview.tsx`). Re-add the import and the two JSX lines; no `data-tour-id` on this page. |
| `proxy.ts` | `"/shared-reports/"` in `publicRoutes` | Opens the public shared report page (`ui/app/(cloudsneeker-public)/shared-reports/[token]`) without a session. Keep the upstream list and re-add the one entry. |
| `auth.config.ts` | `authorized` returns `true` for paths starting with `/shared-reports/` | NextAuth runs `authorized` before `proxy.ts`, so without it signed-out visitors are sent to sign-in. Re-add the one line after the sign-in / sign-up / invitation check. |
| `components/icons/prowler/ProwlerIcons.tsx` | `ProwlerExtended`/`ProwlerShort` render the artwork from `ui/cloudsneeker/brand-logo.tsx` | Keep the component names; they are imported across the app. |
| `components/icons/Icons.tsx` | `LighthouseIcon` re-exports `SeekerIcon` from `ui/cloudsneeker/seeker-icon.tsx` | The assistant mark is a lens, not the inherited glyph. |
| `components/auth/oss/auth-layout.tsx` | re-exports the responsive split-screen experience from `ui/cloudsneeker/auth-layout.tsx` | Form children and submission behavior remain inherited. |
| `components/compliance/threatscore-logo.tsx` | re-exports product artwork from `ui/cloudsneeker/threatscore-logo.tsx` | Prevents inherited vendor artwork from appearing on the overview. |
| `components/layout/app-sidebar/navigation-config.ts` | imports `BRAND`, `docsUrl`, `withCloudsneekerNavigation`; `apiReferenceUrl = apiDocsUrl`; Documentation `docsUrl()`, Support `BRAND.supportUrl`, Check Catalog `docsUrl("checks")`; final `filterNavigationByPermissions(withCloudsneekerNavigation(sections, pathname), permissions)` | `withCloudsneekerNavigation` drops HELP and regroups the upstream items (reused by href) into the product sections: Cloud Security, Application Security, Governance, Operations (Scans plus the built-in cloud features as real links), Settings (Configuration, Organization with Profile). No new hook line. |
| `components/shadcn/custom/custom-link.tsx` | `shouldRenderDocumentationHref(href)` short-circuits docs destinations | Product `BRAND.showDocumentationLinks` is false, so Learn more docs links do not render. |
| `app/(prowler)/alerts/page.tsx` | also allows `isCloudsneekerFeatureEnabled("alerts")` | Opens Alerts without `UI_CLOUD_ENABLED`. |
| `app/(prowler)/compliance/page.tsx` | Multiple Scans enabled when `isCloud() \|\| isCloudsneekerFeatureEnabled("scanComparison")`; non-cloud path renders `ScanComparisonOverview` | Opens Multiple Scans without cloud APIs via scan-to-scan comparison. |
| `app/(prowler)/findings/_components/findings-filters-section.tsx` | `isCloudEnabled={isCloud() \|\| isCloudsneekerFeatureEnabled("alerts")}` | Seed-from-findings works without cloud. |
| `app/(prowler)/scans/config/page.tsx` | also allows `isCloudsneekerFeatureEnabled("scanConfiguration")` | Opens Scan profiles without cloud. |
| `app/api/ingestions/route.ts`, `[ingestionId]/route.ts` | also allow `isCloudsneekerFeatureEnabled("cliImport")` | CLI Import proxy works without cloud. |
| `app/(prowler)/integrations/integrations-content.tsx` | Slack when `isCloud() \|\| isCloudsneekerFeatureEnabled("slack")`; Email card when `emailDelivery` | Unlocks Slack and Email on Integrations. |
| `app/(prowler)/integrations/slack/page.tsx` | also allows `isCloudsneekerFeatureEnabled("slack")` | Opens Slack settings without cloud. |
| `app/(prowler)/integrations/slack/callback/route.ts` | also allows `isCloudsneekerFeatureEnabled("slack")` | Completes Slack OAuth without cloud. |
| `app/(prowler)/integrations/slack/slack-integration-content.tsx` | loads `getSlackAppConfig` and passes `slackAppConfig`/`redirectUri` | Tenant Slack app credentials for OAuth. |
| `components/integrations/slack/slack-integration-manager.tsx` | unavailable state renders `SlackAppConfigForm`; Disconnect gated on `manage_account` | Users save Client ID/Secret in-app; only admin disconnects. |
| `api/v1/views.py` (`IntegrationViewSet.set_required_permissions`) | DELETE requires `Permissions.MANAGE_ACCOUNT` | Only admin may remove integrations. |
| `components/integrations/shared/integration-action-buttons.tsx` | Delete button gated on `manage_account` | S3 / Security Hub / Jira delete matches API. |
| `components/integrations/saml/saml-integration-card.tsx` | Remove gated on `manage_account` | Matches SAML API account permission. |
| `ui/__tests__/app-shell.tsx` | test session includes `manage_account` | Browser Slack disconnect suites keep the control. |
| `ui/__tests__/msw/handlers/slack.ts` | `GET /slack-app-config` empty list | Browser Slack suite does not trip on missing handler. |
| `ui/app/(prowler)/integrations/slack/slack-integration.harness.ts` | unavailable copy matches configure form | Asserts in-app config UI. |
| `api/v1/serializers.py`, `serializer_utils/integrations.py` | Slack credential/config serializers and PATCH channel update | Slack channel save on existing Integration API. |
| `api/utils.py`, `tasks/jobs/connection.py`, `api/v1/views.py` (`IntegrationViewSet.connection`) | Slack connection test and channel guard | Connection check posts confirmations to authorized channels. |
| `components/scans/scans-page-shell.tsx` | CLI Import banner/modal when feature enabled | Uses `manage_scans` via Cloudsneeker permission mapping. |
| `actions/auth/auth.ts` | `withCloudsneekerPermissions(...)` on `/users/me` permissions | Maps `manage_scans` onto alerts/ingestions keys. |
| `components/layout/app-sidebar/app-sidebar-content.tsx` | `aria-label={`${BRAND.name} home`}`; upsell block gated by `BRAND.showUpsell` | — |
| `components/layout/app-sidebar/sidebar-footer.tsx` | footer links read `BRAND` | — |
| `components/auth/oss/sign-up-form.tsx` | terms link `href={BRAND.termsUrl}` | — |
| `components/integrations/saml/saml-config-form.tsx` | SP entity ID `value={BRAND.samlSpEntityId}` | — |
| `components/findings/table/finding-triage-cells.tsx` | `CLOUD_ONLY_TOOLTIP_COPY = BRAND.unavailableFeatureCopy` | — |
| `components/shadcn/badge/badge.tsx` | `variant === "cloud"` renders nothing unless `BRAND.showUpsell` | — |
| `app/(prowler)/attack-paths/(workflow)/query-builder/_components/query-description.tsx` | `documentation_link` only when `showDocumentationLinks()` | Hides the per-query "View on ... documentation" link (docs links are off in the product). |
| `lib/date-utils.ts` | `formatLocalTimeWithZone` zone from `localTimeZoneLabel(date)` (`ui/cloudsneeker/lib/time-zone.ts`) | Shows "IST" / "GMT+5:30" instead of the first three letters of the IANA city ("CAL"). |
| `components/shadcn/breadcrumbs/breadcrumb-navigation.tsx` | `displayName = breadcrumbSegmentLabel(segment, displayName)` | UUID path segments read "Details" (`ui/cloudsneeker/breadcrumbs.ts`). |
| `components/lighthouse-v1/managed-lighthouse-callout.tsx` | renders nothing unless `BRAND.showUpsell` | Hides the managed-AI upsell card on Seeker AI settings. |
| `components/survey/runtime-feedback-survey.tsx` | `SURVEY_NAME = BRAND.surveyName` | — |
| `app/(prowler)/compliance/_components/cross-provider-hub-link.tsx` | `href={docsUrl(`compliance/${id}`)}` | Resolves to the generated framework page in `cloudsneeker/docs`. |
| `app/api/health/route.ts` | `serviceId: BRAND.serviceId` | `cloudsneeker-ui`. |
| `lib/external-urls.ts` | `PROWLER_HUB_URL = BRAND.docsUrl`; `PROWLER_CF_TEMPLATE_URL = BRAND.cloudformationTemplateUrl`; `BILLING_URL`; `DOCS_URLS` built with `docsUrl()` | Keep upstream export names. |
| `lib/cloud-upgrade.ts` | `CLOUD_SIGN_UP_URL = BRAND.websiteUrl`; `PRICING_URL = BRAND.pricingUrl || BRAND.websiteUrl` | — |
| `lib/deployment.ts` | `PROWLER_CLOUD_ONLY_TOOLTIP = BRAND.unavailableFeatureCopy`; `isGroupedJiraDispatchEnabled` also checks `jiraGroupedDispatch` | Keep the export names. |
| `lib/schedules.ts` (`getScanScheduleCapability`) | ADVANCED when `advancedScheduling` is on | Weekly/monthly/interval schedules without cloud edition. |
| `api/v1/urls.py` | `ScheduleViewSet` imported from `cloudsneeker_api.views_schedules` | Full `/schedules` API extends the OSS daily-only viewset; `daily` stays the upstream action. |
| `ui/lib/schedules.test.ts` | capability expectation uses ADVANCED under Cloudsneeker | Matches `advancedScheduling` default. |
| `lib/vulnerability-references.ts` | `HUB` label `View in ${BRAND.name} documentation`; hostname match against the brand docs host | — |
| `lib/lighthouse-v1/system-prompt.ts` | `brandSystemPrompt` from `ui/cloudsneeker/lighthouse-prompt.ts` replaces the product paragraph | The agent speaks as the product and cites product docs. |
| `lib/lighthouse-v1/llm-factory.ts` | `maxRetries: SEEKER_AI_MAX_RETRIES` on every model client | A quota or auth error reaches the chat in seconds instead of after LangChain's six backoff retries. |
| `lib/lighthouse-v1/allowed-tools.ts`, `lib/lighthouse-v1/tools/meta-tool.ts`, `lib/lighthouse-v1/mcp-client.ts`, `app/(prowler)/lighthouse/_lib/tool-calls.ts` | `isAllowedTool` checks `canonicalToolName(name)`; `describe_tool` / `execute_tool` find tools with `isSameToolName`; `handleBeforeToolCall` injects the user's `Authorization` header by canonical name; tool-call labels strip the canonical prefix (`ui/cloudsneeker/lighthouse-tools.ts`, `BRAND.mcpToolNamespace`) | The shipped MCP server names tools `cloudsneeker_<tool>` (rebrand rules `mcp-app-namespace` / `mcp-tool-prefix`); the allowlist and prompt use `prowler_<tool>`, so Seeker AI saw no tools at all. |
| `store/cloud-upgrade/store.ts` | upsell modal opens only when `BRAND.showUpsell` | — |
| `types/findings-triage.ts` | `FINDING_TRIAGE_BILLING_HREF = BRAND.pricingUrl` | — |
| `lib/provider-credentials/provider-credential-fields.ts` | `ProviderCredentialFields.IAC_USERNAME` (`username`), `ECR_ROLE_ARN`, `ECR_EXTERNAL_ID`, `REGISTRY_INSECURE` and the matching `ErrorPointers` | New secret keys for private Git hosts and registries; keep upstream keys untouched. |
| `lib/provider-credentials/build-credentials.ts` | `buildIacSecret` spreads `buildIacSecretExtras(formData)`; `buildImageSecret` spreads `buildImageSecretExtras(formData)` (`ui/cloudsneeker/lib/provider-secret-extras.ts`) | Extras trim strings, drop empty ones, and send `registry_insecure` as a real boolean. |
| `types/formSchemas.ts` (`addCredentialsFormSchema`) | IaC branch adds optional `username`; image branch adds optional `ecr_role_arn`, `ecr_external_id`, and `registry_insecure` as `z.enum(REGISTRY_INSECURE_VALUES)` | The checkbox stores `"true"`/`"false"` so the schema's string-only `superRefine` record type still holds; zod would strip the keys otherwise. |
| `types/components.ts` | `IacCredentials` gains `username`; `ImageCredentials` gains `ecr_role_arn`, `ecr_external_id`, `registry_insecure` (type import of `RegistryInsecureValue`) | — |
| `hooks/use-credentials-form.ts` | image defaults add empty ECR fields and `registry_insecure: REGISTRY_INSECURE_VALUE.OFF` | Default sends `registry_insecure: false`. |
| `components/providers/workflow/forms/via-credentials/iac-credentials-form.tsx` | re-exports `IacCredentialsForm` from `ui/cloudsneeker/components/iac-credentials-form.tsx` | Copy lists GitHub/GitHub Enterprise, GitLab, Bitbucket Cloud & Server, Azure DevOps and other HTTPS Git servers; adds the username field. |
| `components/providers/workflow/forms/via-credentials/image-credentials-form.tsx` | renders `<ImageRegistryExtraFields control={control} />` after the registry token field | "Amazon ECR (IAM)" section (role ARN, external ID) and the insecure-registry checkbox with warning (`ui/cloudsneeker/components/image-registry-extra-fields.tsx`). |

Test-side hooks (UI): `vitest.setup.ts` mocks `@/cloudsneeker/brand` with `showUpsell: true` so upstream upsell suites run unchanged; about twenty `*.test.ts(x)` files read `BRAND` instead of a literal (`navigation-config.test.ts` expects the HELP section to be absent). Two browser suites, `providers-page.integration.test.tsx` and `slack-page.integration.test.tsx`, compare documentation links against `DOCS_URLS` instead of upstream slugs. Upstream suites that assert Cloud-only scheduling, CLI import, or Slack (`use-scan-schedule-capability`, `launch-scan-modal`, `launch-step`, `data-table-row-actions` (providers), `scan-jobs-row-actions`, `scans-page-shell`, `slack/callback/route`) mock `@/cloudsneeker/features` so `isCloudsneekerFeatureEnabled` returns false; `navigation-config.test.ts` mocks `withCloudsneekerNavigation` down to its HELP removal; `slack-integration-manager.test.tsx` mocks `@/cloudsneeker/actions/slack-app` and `@/hooks/use-auth`. Run `rg -n "cloudsneeker-hook" ui --glob "*.test.*"` for the list.

New UI files that sit outside `ui/cloudsneeker/` and `ui/app/(cloudsneeker)/` without editing an upstream file: `ui/app/(cloudsneeker-public)/` (public pages; its `layout.tsx` re-exports the `(auth)` root layout) and `ui/app/api/cloudsneeker/` (route handlers such as the report download proxy).

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
| `Dockerfile` | `RUN chmod +x /app/entrypoint.sh` after the entrypoint copy | The exported build tree does not keep the executable bit. |
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
