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
| `prowler/providers/aws/services/awslambda/awslambda_service.py` | `from cloudsneeker.sdk_concurrency import iter_bounded`; `_get_function_code` and `_get_layers_code` loop over `iter_bounded(self.thread_pool, ...)` instead of submitting every download and `as_completed` | Keeps at most 8 code downloads in memory. Upstream held every function's zip until the last download ended; one AWS scan reached 13.7 GB and was OOM-killed. |
| `prowler/providers/iac/iac_provider.py` | `from cloudsneeker.git_auth import (authenticated_clone_url, iac_clone_url, redact, redact_exception)`; `__init__` and `test_connection` take `username: str = None`; `self.git_username = username`; `_clone_repository` builds the URL with `iac_clone_url(repository_url, github_username, personal_access_token, oauth_app_token, getattr(self, "git_username", None))` and its `except` starts with `error = redact_exception(error, personal_access_token, oauth_app_token)`; `test_connection` uses `auth_url = authenticated_clone_url(scan_repository_url, oauth_app_token, username)` and `error_msg = redact(str(e), oauth_app_token)`; unused `import re` removed | Replace upstream's github.com-only `replace()` block in `_clone_repository` and the `x-access-token` regex block in `test_connection` with the single helper calls, so the clone and the connection test build the same per-host URL (GitHub `x-access-token`, GitLab `oauth2`, Bitbucket `x-token-auth` or `<username>`, Azure DevOps `pat`; table in `cloudsneeker/git_auth.py`). Tokens never appear in logs or errors. |
| `prowler/providers/iac/iac_provider.py` (SSH) | `from cloudsneeker import git_ssh`; `from dulwich import porcelain` kept with `# noqa: F401` (tests patch it); `__init__` and `test_connection` take `ssh_private_key`, `ssh_known_hosts`, `ssh_key_passphrase`; `self.git_ssh` holds them; the three `porcelain.clone` calls become `git_ssh.clone(..., *getattr(self, "git_ssh", ()), depth=1)` and `porcelain.ls_remote` becomes `git_ssh.ls_remote(auth_url, ...)` | `git@host:owner/repo.git` and `ssh://` repository URLs clone with a deploy key through `cloudsneeker/git_ssh.py` (pinned host keys, strict host checking). HTTPS clones call `porcelain.clone` exactly as before. |

Test-side hooks (SDK): `tests/conftest.py` applies `cloudsneeker.testing.UPSTREAM_COMPAT_ENV` before any `prowler` import so upstream suites still assert upstream names; `tests/config/config_test.py`, `tests/lib/outputs/html/html_test.py`, and `tests/lib/outputs/slack/slack_test.py` read the brand instead of literal strings. `tests/cloudsneeker/conftest.py` swaps the module-level `brand` back to the shipped defaults for Cloudsneeker's own tests; `tests/cloudsneeker/hooks_test.py` imports the hooked modules in a clean subprocess and proves they print the shipped names. `tests/providers/iac/iac_provider_test.py::test_clone_repository_with_oauth` expects `x-access-token:` instead of `oauth2:` for github.com (marked line); `tests/cloudsneeker/git_auth_test.py` covers the helper and both IaC hooks.

## API (`api/src/backend/`)

| File | Hook | Re-apply by |
| --- | --- | --- |
| `config/django/base.py` | `from cloudsneeker_api.brand import brand`; `"cloudsneeker_api"` appended to `INSTALLED_APPS`; `"cloudsneeker_api.audit.AuditLogMiddleware"` appended to `MIDDLEWARE` (audit log, EB-007; must stay after `AuthenticationMiddleware` so DRF has set `request.user` / `request.auth` when it reads them); `"cloudsneeker_api.mfa.MfaMiddleware"` after the sign-up gate (EB-008: `POST /tokens` needs `otp_code` once a password user has MFA on, fails closed; members of a tenant that requires MFA who have not enrolled only reach `/mfa*`, `/tokens*` and session reads); `"cloudsneeker_api.login_guard.LoginGuardMiddleware"` between the sign-up gate and MFA (per-account sign-in lockout: `CLOUDSNEEKER_LOGIN_MAX_FAILURES` 401s from `POST /tokens` within `CLOUDSNEEKER_LOGIN_LOCKOUT_SECONDS` answer 429 `sign_in_locked`; keyed by email, not IP, because sign-in arrives from the web app's servers; fails open); `CACHES = shared_cache_settings()` (`cloudsneeker_api/cache_settings.py`: `default` stays local memory, `cloudsneeker-shared` is Valkey DB `CLOUDSNEEKER_CACHE_VALKEY_DB`, default 3); `"cloudsneeker_api.signup.SignupGateMiddleware"` after the audit middleware (EB-002: refuses `POST /users` without `invitation_token` when `CLOUDSNEEKER_SELF_REGISTRATION_ENABLED=false` and users exist; fails closed); `"cloudsneeker_api.subscriptions.SubscriptionEnforcementMiddleware"` appended last (operator console Phase 1: plan enforcement before the view; reads only headers, fails open); `SECURE_HSTS_SECONDS` from `DJANGO_SECURE_HSTS_SECONDS` (default 0) and `SECURE_HSTS_INCLUDE_SUBDOMAINS` when it is positive (EB-015; `platform.yaml` sets a year only on HTTPS stacks); `SPECTACULAR_SETTINGS["TITLE"] = f"API Reference - {brand.name}"`; `SIMPLE_JWT` issuer and audience default to `brand.jwt_default_issuer` | Keep upstream env-var names (`DJANGO_TOKEN_ISSUER`, `DJANGO_TOKEN_AUDIENCE`). |
| `config/urls.py` | `path("api/v1/", include("cloudsneeker_api.urls"))` after the upstream `api.v1.urls` include | Brand under `/api/v1/cloudsneeker/`; also mounts alerts, scan-configurations, and ingestions contracts the UI already calls. |
| `config/celery.py` | `autodiscover_tasks(["api", "cloudsneeker_api"])` | Loads Cloudsneeker ingestion and alert tasks. |
| `api/models.py` (key rotation) | `from cloudsneeker_api.crypto import build_fernet`; `fernet = build_fernet(settings.SECRETS_ENCRYPTION_KEY)` instead of `Fernet(...)` | EB-016. A `MultiFernet` that also reads `DJANGO_SECRETS_ENCRYPTION_KEY_PREVIOUS`; same `encrypt`/`decrypt` API. Runbook: `encryption-key-rotation.md`. |
| `config/django/base.py` (API keys) | `DRF_API_KEY["FERNET_SECRET"]` reads `DJANGO_API_KEY_FERNET_SECRET`, falling back to the data key | EB-016. Rotating the data key must not revoke API keys. |
| `config/django/testing.py` | appended block: `CACHES["cloudsneeker-shared"]` is local memory and `CLOUDSNEEKER_LOGIN_GUARD_ENABLED = False` | Unit tests have no Valkey, and fixtures that sign in with wrong passwords would trip the lockout. `cloudsneeker_api/tests/test_login_guard.py` turns it back on. |
| `config/settings/social_login.py` | SAML `"entity_id": brand.saml_sp_entity_id` | `urn:cloudsneeker:sp`; must match `ui/cloudsneeker/brand.ts` `samlSpEntityId`. |
| `config/settings/social_login.py` (SAML hardening) | `SOCIALACCOUNT_ADAPTER = "cloudsneeker_api.saml.CloudsneekerSocialAccountAdapter"` | EB-009. The subclass keeps every upstream adapter behavior and, on each `get_app` for a SAML app, requires signed assertions, signs AuthnRequests and logout requests with `SAML_PUBLIC_CERT` / `SAML_PRIVATE_KEY` (Secrets Manager keys `samlSpCert` / `samlSpKey`, created by `deploy.ps1`), and applies the tenant's `reject_idp_initiated_sso` (`TenantSsoPolicy`). Stored `SocialApp.settings` stay as upstream wrote them. If upstream renames the adapter, point the subclass at the new class. |
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
| `api/v1/serializers.py` (SSH) | `from cloudsneeker_api.secret_extras import validate_iac_ssh_secret`; `IacProviderSecret` gains optional `ssh_private_key`, `ssh_known_hosts`, `ssh_key_passphrase` and `validate()` calls `validate_iac_ssh_secret(attrs)` | Rejects unreadable keys, keys on HTTPS URLs, and self-hosted SSH servers without a host key. |
| `api/Dockerfile` | `openssh-client` in the first `apt-get install` list, with a `# cloudsneeker-hook` comment above the `RUN` | Dulwich's SSH transport runs the `ssh` client. Installed explicitly, so the later purge of `git` keeps it. |
| `api/utils.py` | `from cloudsneeker_api.ecr_auth import apply_ecr_auth, ecr_connection_kwargs`; `get_prowler_provider_kwargs` IaC branch passes `username` when the secret has one, image branch starts with `prowler_provider_kwargs = apply_ecr_auth(provider.uid, prowler_provider_kwargs)`; `prowler_provider_connection_test` IaC branch passes `username`, image branch starts with `ecr_failure, prowler_provider_kwargs = ecr_connection_kwargs(...)` and returns `ecr_failure` when set | ECR tokens expire after 12 hours, so the worker mints one per scan / connection test (`ecr:GetAuthorizationToken`, optional `sts:AssumeRole` with `ExternalId`) when the uid is an ECR host and no static registry credentials are stored. `ecr_role_arn` / `ecr_external_id` are stripped before `ImageProvider`. |
| `api/utils.py` (SSH) | `from cloudsneeker_api.secret_extras import iac_ssh_kwargs`; the IaC branches of `get_prowler_provider_kwargs` and `prowler_provider_connection_test` add `iac_ssh_kwargs(secret)` | Scans and connection checks pass the stored SSH key to `IacProvider`. |
| `Dockerfile` | `RUN chmod +x ./docker-entrypoint.sh` after the entrypoint copy | The exported build tree does not keep the executable bit. | |

Test-side hooks (API): `conftest.py` imports the autouse fixture `cloudsneeker_api.testing.upstream_compat_brand`, which swaps `cloudsneeker_api.brand.brand` for `cloudsneeker.testing.UPSTREAM_COMPAT_ENV` values in every test outside `cloudsneeker_api/` (so `test_reports_ens.py` still finds "Prowler" in the PDF footer). `.github/workflows/cloudsneeker-tests.yml` deselects `TestScheduleViewSet::test_schedule_invalid_method_list[get]`: the Cloudsneeker `ScheduleViewSet` serves `GET /schedules` on purpose, so the upstream OSS 405 expectation cannot hold. `api/tests/test_views.py`, `tasks/tests/test_integrations.py`, and `tasks/tests/test_reports_base.py` assert against `cloudsneeker_api.brand` values. `cloudsneeker_api/tests/` covers the brand helpers, the app registration, `/api/v1/cloudsneeker/brand`, and the OpenAPI entry.

## UI (`ui/`)

| File | Hook | Re-apply by |
| --- | --- | --- |
| `config/site.ts` | `siteConfig.name` and `description` read `BRAND` | Comment line marks the file; no literal name. |
| `app/(prowler)/page.tsx` | `import { RiskOverview } from "@/cloudsneeker/components/risk-overview"; // cloudsneeker-hook` and `{/* cloudsneeker-hook: one risk view across every product area */}` + `<RiskOverview />` after `<OverviewProviderContext />` | Overview risk view (score, severity totals, areas, top risks, trend) from the latest completed executive report run (`ui/cloudsneeker/components/risk-overview.tsx`). Re-add the import and the two JSX lines; no `data-tour-id` on this page. |
| `proxy.ts` | `"/shared-reports/"` in `publicRoutes` | Opens the public shared report page (`ui/app/(cloudsneeker-public)/shared-reports/[token]`) without a session. Keep the upstream list and re-add the one entry. |
| `auth.config.ts` (MFA) | `withOtpCode` import; credentials provider declares `otpCode`, the zod schema accepts it (optional), and `getToken(withOtpCode({ email, password }, otpCode))` | EB-008. Without it the second sign-in step drops the code. |
| `auth.config.ts` | `authorized` returns `true` for paths starting with `/shared-reports/` | NextAuth runs `authorized` before `proxy.ts`, so without it signed-out visitors are sent to sign-in. Re-add the one line after the sign-in / sign-up / invitation check. |
| `components/icons/prowler/ProwlerIcons.tsx` | `ProwlerExtended`/`ProwlerShort` render the artwork from `ui/cloudsneeker/brand-logo.tsx` | Keep the component names; they are imported across the app. |
| `components/icons/Icons.tsx` | `LighthouseIcon` re-exports `SeekerIcon` from `ui/cloudsneeker/seeker-icon.tsx` | The assistant mark is a lens, not the inherited glyph. |
| `components/auth/oss/auth-layout.tsx` | re-exports the responsive split-screen experience from `ui/cloudsneeker/auth-layout.tsx` | Form children and submission behavior remain inherited. |
| `components/compliance/threatscore-logo.tsx` | re-exports product artwork from `ui/cloudsneeker/threatscore-logo.tsx` | Prevents inherited vendor artwork from appearing on the overview. |
| `components/layout/app-sidebar/navigation-config.ts` | imports `BRAND`, `docsUrl`, `withCloudsneekerNavigation`; `apiReferenceUrl = apiDocsUrl`; Documentation `docsUrl()`, Support `BRAND.supportUrl`, Check Catalog `docsUrl("checks")`; final `filterNavigationByPermissions(withCloudsneekerNavigation(sections, pathname), permissions)` | `withCloudsneekerNavigation` drops HELP and regroups the upstream items (reused by href) into the product sections: Cloud Security, Application Security, Governance, Operations (Scans plus the built-in cloud features as real links), Settings (Configuration, Organization with Profile). No new hook line. |
| `components/shadcn/custom/custom-link.tsx` | `shouldRenderDocumentationHref(href)` short-circuits docs destinations | Product `BRAND.showDocumentationLinks` is false, so Learn more docs links do not render. |
| `app/(prowler)/alerts/page.tsx` | also allows `isCloudsneekerFeatureEnabled("alerts")`; `import { AlertsSummary } from "@/cloudsneeker/components/alerts-summary"; // cloudsneeker-hook` and `{/* cloudsneeker-hook: key figures above the alerts list */}` + `<AlertsSummary alerts={alerts} totalCount={apiMeta?.pagination?.count} unavailable={Boolean(hasError)} />` as the first child of `ContentLayout` | Opens Alerts without `UI_CLOUD_ENABLED`; KPI tiles (rules, active, paused, destinations) from `ui/cloudsneeker/components/alerts-summary.tsx`. Re-add the import and the two JSX lines; no `data-tour-id` on this page. |
| `app/(prowler)/compliance/page.tsx` | Multiple Scans enabled when `isCloud() \|\| isCloudsneekerFeatureEnabled("scanComparison")`; non-cloud path renders `ScanComparisonOverview`; Single Scan default `defaultComplianceScanId(expandedScansData)` instead of `expandedScansData[0]?.id` | Opens Multiple Scans without cloud APIs via scan-to-scan comparison. Without a `scanId` the page opens the newest scan whose provider has compliance frameworks, skipping IaC and image scans (`ui/cloudsneeker/compliance/default-scan.ts`). |
| `app/(prowler)/findings/_components/findings-filters-section.tsx` | `isCloudEnabled={isCloud() \|\| isCloudsneekerFeatureEnabled("alerts")}` | Seed-from-findings works without cloud. |
| `app/(prowler)/scans/config/page.tsx` | also allows `isCloudsneekerFeatureEnabled("scanConfiguration")`; `import { ScanProfilesSummary } from "@/cloudsneeker/components/scan-profiles-summary"; // cloudsneeker-hook` and `{/* cloudsneeker-hook: key figures above the scan profiles list */}` + `<ScanProfilesSummary profiles={configs} providerIds={richProviders.map((provider) => provider.id)} />` before `ScanConfigurationsManager` | Opens Scan profiles without cloud; KPI tiles (profiles, providers with a profile, providers on defaults, last edited). `page.test.ts` still passes (no `getAllProviders`). |
| `app/(prowler)/alerts/_components/alerts-table.tsx` | `import { AlertStatusBadge } from "@/cloudsneeker/components/alert-status-badge"; // cloudsneeker-hook` and the `enabled` column `cell` returns `<AlertStatusBadge enabled={row.original.attributes.enabled} />` (marked `// cloudsneeker-hook: status pill instead of plain text`) | Status pill (success when enabled, neutral when disabled) with the same "Enabled" / "Disabled" text, so sorting and tests are unchanged. Re-add the import and replace the plain-text `cell` again; no `data-tour-id` in this file. |
| `app/api/ingestions/route.ts`, `[ingestionId]/route.ts` | also allow `isCloudsneekerFeatureEnabled("cliImport")` | CLI Import proxy works without cloud. |
| `app/(prowler)/integrations/integrations-content.tsx` | Slack when `isCloud() \|\| isCloudsneekerFeatureEnabled("slack")`; Email card when `emailDelivery`; `BitbucketIntegrationCard` (import marked `// cloudsneeker-hook`) when `bitbucketImport` | Unlocks Slack and Email on Integrations, and links to the Bitbucket workspace import (`/integrations/bitbucket`). |
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
| `components/scans/import-findings-modal.tsx` | `import { CliImportSteps } from "@/cloudsneeker/components/cli-import-steps"; // cloudsneeker-hook` and `{/* cloudsneeker-hook: how-to above the upload area */}` + `<CliImportSteps />` before the `import-findings-dropzone` div | Numbered how-to (CLI command with `--output-formats json-ocsf`, pick the `.ocsf.json`, start import). `theme.css` styles the status paragraphs that follow it (`[data-slot="cli-import-steps"] ~ p`), so the modal body is not edited further. |
| `actions/auth/auth.ts` (MFA) | `getToken` adds `...otpCodeAttribute(formData)`, calls `throwIfMfaChallenge(response)` before returning `null`, and `rethrowMfaChallenge(error)` in its catch; `authenticate` returns `mfaSignInResult(error)` first | EB-008 (`ui/cloudsneeker/lib/mfa-server.ts`). The challenge is a `CredentialsSignin` whose `code` is `mfa_required` or `mfa_invalid`. |
| `components/auth/oss/sign-in-form.tsx` (MFA) | `mfaChallenge` / `otpCode` state; credentials built with `withOtpCode`; an `isMfaChallengeCode(result.message)` branch before the success check; `<MfaCodeField>` under the password field | EB-008. Re-add after the upstream password field. |
| `actions/auth/auth.ts` | `withCloudsneekerPermissions(...)` on `/users/me` permissions | Maps `manage_scans` onto alerts/ingestions keys. |
| `components/layout/app-sidebar/app-sidebar-content.tsx` | `aria-label={`${BRAND.name} home`}`; upsell block gated by `BRAND.showUpsell`; imports `useCloudsneekerPlan` (`@/cloudsneeker/lib/plan-store`) and `withCloudsneekerPlan` (`@/cloudsneeker/navigation`); `const cloudsneekerPlan = useCloudsneekerPlan();` and `const sections = withCloudsneekerPlan(getNavigationConfig({...}), cloudsneekerPlan);` | Operator console Phase 1: hides sidebar links for features outside the plan and adds "Operator console" under Organization for platform operators. The plan is an argument of the render (not module state read inside `getNavigationConfig`), so the React Compiler recomputes the sections when the plan loads. Re-add the two imports, the hook call, and wrap the upstream `getNavigationConfig({...})` call. |
| `app/(prowler)/layout.tsx` | `import { CloudsneekerPlanStatus } from "@/cloudsneeker/components/plan-status"; // cloudsneeker-hook` and `{/* cloudsneeker-hook: ... */}` + `<Suspense fallback={null}><CloudsneekerPlanStatus /></Suspense>` right before `<MainLayout>` | Loads `/entitlements` and `/operator/me` once per layout render, seeds the plan store for the sidebar, and shows the fixed subscription banner (suspended, expired, cancelled, or ending within 7 days). Fails open. |
| `app/(prowler)/profile/page.tsx` | `import { PlanSummaryCard } from "@/cloudsneeker/components/plan-summary-card"; // cloudsneeker-hook` and `{/* cloudsneeker-hook: plan name and end date */}` + `<PlanSummaryCard />` after `<UserBasicInfoCard>` | Plan name, status, end date and limited usage on the profile page; renders nothing when entitlements fail to load. `page.test.ts` section order is unaffected. |
| `components/layout/app-sidebar/sidebar-footer.tsx` | footer links read `BRAND` | — |
| `components/auth/oss/sign-up-form.tsx` | terms link `href={BRAND.termsUrl}` | — |
| `components/integrations/saml/saml-config-form.tsx` | SP entity ID `value={BRAND.samlSpEntityId}` | — |
| `components/findings/table/finding-triage-cells.tsx` | `CLOUD_ONLY_TOOLTIP_COPY = BRAND.unavailableFeatureCopy` | — |
| `components/shadcn/badge/badge.tsx` | `variant === "cloud"` renders nothing unless `BRAND.showUpsell` | — |
| `app/(prowler)/attack-paths/(workflow)/query-builder/_components/query-description.tsx` | `documentation_link` only when `showDocumentationLinks()` | Hides the per-query "View on ... documentation" link (docs links are off in the product). |
| `proxy.ts` (HSTS) | `withSecurityHeaders` returns `applySecurityHeaders(response)` (`ui/cloudsneeker/lib/security-headers.ts`) | EB-015. Adds `Permissions-Policy` (camera, microphone, geolocation, USB, payment off) and, through `applyHsts` (`ui/cloudsneeker/lib/hsts.ts`), `Strict-Transport-Security` when `CLOUDSNEEKER_HSTS_SECONDS` is positive; `next.config.js` headers are fixed at build time, so the runtime headers live here. |
| `app/api/auth/[...nextauth]/route.ts` | `GET` / `POST` wrapped in `withoutSessionTokens(handlers.X)` (`ui/cloudsneeker/lib/session-response.ts`) | Removes `accessToken` / `refreshToken` from the `/api/auth/session` JSON so page scripts cannot read API tokens. Server code uses `auth()` and still sees them. `tests/helpers.ts` `verifySessionValid` asserts they are absent. |
| `lib/shared/env.ts` | `isSelfRegistrationEnabled()` returns `isCloudsneekerSelfRegistrationEnabled()` (`ui/cloudsneeker/lib/self-registration.ts`) instead of `true` outside cloud mode | EB-002: `CLOUDSNEEKER_SELF_REGISTRATION_ENABLED=false` hides the sign-up link, redirects `/sign-up` without an invitation to `/sign-in`, and hides "create organization". Cloud mode keeps the upstream flag. |
| `lib/date-utils.ts` | `formatLocalTimeWithZone` zone from `localTimeZoneLabel(date)` (`ui/cloudsneeker/lib/time-zone.ts`) | Shows "IST" / "GMT+5:30" instead of the first three letters of the IANA city ("CAL"). |
| `components/shadcn/breadcrumbs/breadcrumb-navigation.tsx` | `displayName = breadcrumbSegmentLabel(segment, displayName)`; `isClickable: !isLast && isBreadcrumbPathLinkable(currentPath)` | UUID path segments read "Details"; segments with no page of their own (`/settings`) are plain text, not a link to a 404 (`ui/cloudsneeker/breadcrumbs.ts`). |
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
| `actions/findings/findings-triage.options.ts` | `isCloud() \|\| isCloudsneekerFeatureEnabled("findingTriage")` (import + one expression, both marked) | Finding triage (EB-010): the inherited triage column, status selector, drawer control and note modal are editable without `UI_CLOUD_ENABLED`; they call the `cloudsneeker_api` finding-triage routes (`knowledge-base/finding-triage.md`). |
| `actions/findings/findings.ts` (`getFindings`, `getLatestFindings`, `getFindingById`), `actions/finding-groups/finding-groups.ts` (`fetchFindingGroupResourcesEndpoint`), `actions/findings/findings-by-resource.ts` (`getLatestFindingsByResourceUid`) | `import { withCloudsneekerTriage } from "@/cloudsneeker/lib/finding-triage-server"; // cloudsneeker-hook` and the response wrapped as `withCloudsneekerTriage(await handleApiResponse(...))` | Adds `triage_status`, `triage_id` and note counts from `GET /finding-triages/lookup` to finding rows that carry no triage fields (the open-source findings API never sends them). Errors leave the response unchanged. Re-add the import and wrap the `handleApiResponse` result at each call. |
| `actions/findings/findings.test.ts`, `actions/finding-groups/finding-groups.adapter.test.ts` | triage DTO expectations use `canEdit: true` (no `CLOUD_ONLY` reason) | Matches the `findingTriage` default. |
| `lib/provider-credentials/provider-credential-fields.ts` | `ProviderCredentialFields.IAC_USERNAME` (`username`), `ECR_ROLE_ARN`, `ECR_EXTERNAL_ID`, `REGISTRY_INSECURE` and the matching `ErrorPointers` | New secret keys for private Git hosts and registries; keep upstream keys untouched. |
| `lib/provider-credentials/provider-credential-fields.ts` (SSH) | `SSH_PRIVATE_KEY`, `SSH_KNOWN_HOSTS`, `SSH_KEY_PASSPHRASE` and their `ErrorPointers` | IaC SSH deploy key fields. |
| `lib/provider-credentials/build-credentials.ts` | `buildIacSecret` spreads `buildIacSecretExtras(formData)`; `buildImageSecret` spreads `buildImageSecretExtras(formData)` (`ui/cloudsneeker/lib/provider-secret-extras.ts`) | Extras trim strings, drop empty ones, and send `registry_insecure` as a real boolean. |
| `types/formSchemas.ts` (`addCredentialsFormSchema`) | IaC branch adds optional `username`; image branch adds optional `ecr_role_arn`, `ecr_external_id`, and `registry_insecure` as `z.enum(REGISTRY_INSECURE_VALUES)` | The checkbox stores `"true"`/`"false"` so the schema's string-only `superRefine` record type still holds; zod would strip the keys otherwise. |
| `types/formSchemas.ts` (SSH) | IaC branch adds optional `ssh_private_key`, `ssh_known_hosts`, `ssh_key_passphrase` | — |
| `components/providers/workflow/forms/connect-account-form.tsx` | IaC repository URL placeholder also shows `git@github.com:user/repo.git` | Points users at SSH URLs. |
| `types/components.ts` | `IacCredentials` gains `username`; `ImageCredentials` gains `ecr_role_arn`, `ecr_external_id`, `registry_insecure` (type import of `RegistryInsecureValue`) | — |
| `types/components.ts` (SSH) | `IacCredentials` gains `ssh_private_key`, `ssh_known_hosts`, `ssh_key_passphrase` | — |
| `hooks/use-credentials-form.ts` | image defaults add empty ECR fields and `registry_insecure: REGISTRY_INSECURE_VALUE.OFF` | Default sends `registry_insecure: false`. |
| `components/providers/workflow/forms/via-credentials/iac-credentials-form.tsx` | re-exports `IacCredentialsForm` from `ui/cloudsneeker/components/iac-credentials-form.tsx` | Copy lists GitHub/GitHub Enterprise, GitLab, Bitbucket Cloud & Server, Azure DevOps and other HTTPS Git servers; adds the username field. |
| `components/providers/workflow/forms/via-credentials/image-credentials-form.tsx` | renders `<ImageRegistryExtraFields control={control} />` after the registry token field | "Amazon ECR (IAM)" section (role ARN, external ID) and the insecure-registry checkbox with warning (`ui/cloudsneeker/components/image-registry-extra-fields.tsx`). |

CSS-only overrides (no upstream edit): `ui/cloudsneeker/theme.css` fixes the phone navbar (`components/layout/nav-bar/navbar-client.tsx`) below the 40rem `sm` breakpoint. It targets `header.sticky.top-0 > div` and its first/last child groups (title truncates, action group keeps its own width, smaller gaps) and hides `a[aria-label="Open profile"]` (duplicate of the avatar link) and the updates feed button (`Check for updates` / `New updates available...`). If upstream changes that header structure or those labels, update the selectors; `ui/cloudsneeker/theme.test.ts` asserts the rules exist.

CSS-only overrides for Alerts and Scan profiles (no upstream edit): `ui/cloudsneeker/styles/ops-surfaces.css`, imported from the top of `ui/cloudsneeker/theme.css` after `surfaces.css`, keeps only what exists on `/alerts` and `/scans/config`: the empty-state cards (`[data-cloudsneeker-surface="alerts"] ~ * > [data-slot="card"]`, `[data-cloudsneeker-surface="scan-profiles"] ~ [data-slot="card"]`), the inset Filters card of the alert edit dialog and the config path chip of the scan profile editor (scoped by the field ids `#alert-name` and `#scan-configuration-name`). After a merge, check that `AlertsManager` still renders the empty-state `Card` as a direct child, that `ScanConfigurationsManager` still returns a fragment, and that the two field ids remain.

Design system (2026-11-09; rules in `design-system.md`):

| File | Hook | Re-apply by |
| --- | --- | --- |
| `ui/styles/globals.css` | `@import "../cloudsneeker/styles/design-tokens.css"; /* cloudsneeker-hook: design tokens */` right after the `./tours.css` import | Must stay with the other `@import` lines, above `@plugin`. It names the Cloudsneeker tokens and the missing stock shadcn colors (`muted-foreground`, `popover`, `accent`, `destructive`, `ring`, ...) for Tailwind so those classes generate utilities. |
| `ui/app/(prowler)/layout.tsx` | `import { SkipToContent } from "@/cloudsneeker/components/skip-to-content";` and `<SkipToContent />` as the first child of `<body>` | Keyboard skip link to `main[data-responsive-container]` (`components/layout/main-layout`). If upstream renames that attribute, update `MAIN_CONTENT_SELECTOR`. |

Product dashboards (2026-11-09; structure in `dashboards.md`):

| File | Hook | Re-apply by |
| --- | --- | --- |
| `ui/app/(prowler)/page.tsx` | Imports of `ExecutiveOverview` and `isCloudsneekerFeatureEnabled`, then `if (isCloudsneekerFeatureEnabled("executiveOverview")) return <ExecutiveOverview />;` as the first line of `Home` | Keep the upstream body below it untouched. The upstream widgets render on `ui/app/(cloudsneeker)/cloud-security/page.tsx`, which copies the widget layout of `Home`: when upstream adds, removes or reorders an Overview widget, mirror it there. |

CSS-only overrides, app-wide (no upstream edit): `ui/cloudsneeker/styles/surfaces.css`, imported first in `ui/cloudsneeker/theme.css`. It gives every shadcn `Table` (selected by the `border-spacing-y-4` class `components/shadcn/table/table.tsx` puts on `<table>`) square, divided rows instead of pill rows; frames the `DataTable` root (`[data-table-scroll-container]`, pagination `aria-label="Go to ..."` as its last child); styles every `[data-slot="dialog-content"]` and `[role="alertdialog"]`, the dialog overlay, title, description and close button; the floating menus (`dropdown-menu-content`, `select-content`, `multiselect-content`, `popover-content`); `field-label`; the tabs (`tabs-list`, `tabs-trigger`: product colors in place of the upstream green); the card shadow; a base-layer `:focus-visible` outline; and reduced-motion transitions. After a merge, check that `Table` still sets `border-spacing-y-4` and that those `data-slot` values remain; `ui/cloudsneeker/theme.test.ts` asserts the rules exist.

Test-side hooks (UI): `vitest.setup.ts` mocks `@/cloudsneeker/brand` with `showUpsell: true` so upstream upsell suites run unchanged; about twenty `*.test.ts(x)` files read `BRAND` instead of a literal (`navigation-config.test.ts` expects the HELP section to be absent). Two browser suites, `providers-page.integration.test.tsx` and `slack-page.integration.test.tsx`, compare documentation links against `DOCS_URLS` instead of upstream slugs. Upstream suites that assert Cloud-only scheduling, CLI import, or Slack (`use-scan-schedule-capability`, `launch-scan-modal`, `launch-step`, `data-table-row-actions` (providers), `scan-jobs-row-actions`, `scans-page-shell`, `slack/callback/route`) mock `@/cloudsneeker/features` so `isCloudsneekerFeatureEnabled` returns false; `navigation-config.test.ts` mocks `withCloudsneekerNavigation` down to its HELP removal; `slack-integration-manager.test.tsx` mocks `@/cloudsneeker/actions/slack-app` and `@/hooks/use-auth`. Run `rg -n "cloudsneeker-hook" ui --glob "*.test.*"` for the list.

New UI files that sit outside `ui/cloudsneeker/` and `ui/app/(cloudsneeker)/` without editing an upstream file: `ui/app/(cloudsneeker-public)/` (public pages; its `layout.tsx` re-exports the `(auth)` root layout), `ui/app/(operator)/` (operator console; its root `layout.tsx` re-exports the `(auth)` root layout so the tenant sidebar never mounts, and `operator/layout.tsx` shows "Not available" unless `/operator/me` succeeds; `brand_audit.py --source` scans it) and `ui/app/api/cloudsneeker/` (route handlers such as the report download proxy).

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
* Image vulnerability gate (EB-017): `cloudsneeker-images.yml` scans each image with `.github/actions/trivy-scan` before the Azure VM deploy and fails on fixable critical CVEs. Accepted findings live in `cloudsneeker/deploy/trivy/accepted-vulnerabilities.yaml` and are appended to `.trivyignore.yaml` on the runner only.

### Security version bumps

The gate fixes a CVE in an upstream dependency the way upstream would: by moving the pin. After a merge, keep whichever version is newer and relock with the uv version in `.github/actions/setup-python-uv` so the lock revision does not change.

| File | Bump | Reason |
| --- | --- | --- |
| `api/pyproject.toml`, `api/uv.lock` | `pillow==13.0.0` (constraint); `certifi==2026.10.23` (override, constraint line removed) | Critical CVEs in Pillow 12.3.0 and GHSA-6q48-6c7w-9gw2 in certifi. |
| `api/Dockerfile` | `uv==0.13.4` | GHSA-hq85-5cpj-mr62 in uv 0.12.0. |
| `mcp_server/uv.lock` | Authlib 1.9.1, certifi 2026.10.23 | CVE-2026-96760, GHSA-6q48-6c7w-9gw2. |
| `ui/package.json`, `ui/pnpm-lock.yaml` | `next` 16.4.1 | GHSA-2464-fhr4-w9xw, GHSA-673q-mjm6-r5xr in 16.3.6. |

## Platform Integration Hooks (2026-11-11)

See [Platform Integration Audit](platform-integration/PLATFORM_INTEGRATION_AUDIT.md).

| File | Hook | Re-apply by |
| --- | --- | --- |
| `ui/app/(prowler)/alerts/_types/index.ts` | `AREA: "area"` in `ALERT_FILTER_FIELDS` | Keep the upstream fields; add the one key. |
| `ui/app/(prowler)/alerts/_lib/alert-adapter.ts` | `area: ALERT_AREA_FILTER_KEY` in `SIMPLE_FIELD_TO_FINDINGS_FILTER` | One map entry plus the import. |
| `ui/app/(prowler)/alerts/_components/alert-form-modal.tsx` | `editableFilters`, `initialAreas` props; `filtersEditable` replaces `editingAlert` as the filter, test and seed gate; `AlertAreaField` in the Filters card | Re-add the two props and swap the four `editingAlert` checks. |
| `ui/app/(prowler)/alerts/_components/alerts-manager.tsx` | "New alert" button, `newAlertAreas` state, create branch in `submitAlert`, `initialNewArea` prop | Keep upstream edit flow; re-add the create branch. |
| `ui/app/(prowler)/alerts/_components/alerts-table.tsx` | Modules column | One column definition. |
| `ui/app/(prowler)/alerts/page.tsx` | `initialNewArea={requestedNewAlertArea(...)}`; `AlertsTabs` above the summary; `?tab=history` returns early with `AlertHistory` fed by `listAlertEvents(alertHistoryQuery(...))` | One prop, one tab bar, one early return. |
| `ui/app/(prowler)/compliance/page.tsx` | Parallel `getScans` with `complianceScanFilters()`; `expandedScansData = eligibleComplianceScans(allExpandedScans)` outside the Cloud edition; Multiple Scans reads `complianceScanFilters()`; scan choice and metadata from `selectComplianceScan(..., loadComplianceMetadata)`, and `ComplianceUnavailable` replaces the grid and ThreatScore when the scan's compliance task failed | Keep the upstream fetch untouched (its tests assert it). |
| `ui/components/compliance/compliance-header/compliance-filters.tsx` | `ComplianceScopeSelectors`, `scansInScope`, `RunComplianceScanLink` behind the `complianceScope` flag | Three lines inside the filter row. |
| `ui/lib/lighthouse-v1/allowed-tools.ts` | `...CLOUDSNEEKER_AREA_TOOLS` in `ALLOWED_TOOLS` | One spread plus the import. |
| `mcp_server/prowler_mcp_server/prowler_app/server.py` | Second `load_all_tools` for `prowler_mcp_server.cloudsneeker.tools` | One line after the upstream loader. |
| `api/src/backend/cloudsneeker_api/signals.py` (Cloudsneeker file) | `post_save` / `post_delete` on upstream `MuteRule` | Not an upstream edit; listed because it reacts to an upstream model. |

## Adding a Hook

1. Exhaust an extension point first: `cloudsneeker/`, `api/src/backend/cloudsneeker_api/` (new route in `urls.py`), `ui/cloudsneeker/navigation.ts`, `ui/app/(cloudsneeker)/`.
2. If the change is display copy, add or widen a rule in `rebrand.rules.toml` and extend the rebrand fixture test. Do not edit the upstream file.
3. If registration is still required, add a new field to the brand module when a value is needed, make the smallest edit, and put `cloudsneeker-hook` on that line.
4. Add a row to the matching table above with the file, the hook, and how to re-apply it after a merge.
5. Cover it: a Cloudsneeker test asserts the shipped value; if an upstream test asserted the old literal, make it read the brand and mark that line too.
