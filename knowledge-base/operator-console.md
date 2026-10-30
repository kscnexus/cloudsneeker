# Operator Console and SaaS Operations

Design for running Cloudsneeker as a business: managing customers, plans and
licences; seeing platform health, upgrades and alerts; observability; shipping
into customer environments; and selling through the AWS and Azure
marketplaces. Written 2026-10-31.

## Decision: same codebase, separate surface

The operator console lives in this repository, not a separate app:

- It needs cross-tenant reads of the same database (tenants, users, scans,
  findings counts), which the API already reaches through the admin database
  alias (`MainRouter.admin_db`).
- One deploy and one upgrade path keep operations simple.

It is still isolated from customer use:

| Concern | Control |
| --- | --- |
| Who can use it | A `PlatformOperator` table (user, role: `owner`, `support`, `billing`, `read_only`). A tenant role, even an admin one, never grants operator access. |
| Where it is served | API under `/api/v1/operator/*`; UI under a separate route group `ui/app/(operator)/operator/*` with its own layout (no tenant sidebar). |
| Network | WAF rule limits `/operator*` and `/api/v1/operator/*` to an allow-listed IP set (office or VPN). Later: a separate hostname such as `ops.kscnexus.com`. |
| Authentication | Operator endpoints require MFA once EB-008 lands; until then the IP allow-list is mandatory. Short operator sessions. |
| Accountability | Every operator action writes an `OperatorAuditEvent` (actor, tenant affected, action, before/after field names). Customers can be shown operator access to their tenant in their own audit log. |
| Least privilege | `support` can view and impersonate read-only; `billing` manages plans and subscriptions; only `owner` can suspend or delete a tenant. |

## Phase 1: Customers, plans, licences, usage

Status: built (pending deploy). Code: `api/src/backend/cloudsneeker_api/`
(`models.py` operator section, `services/plan_catalog.py`,
`services/entitlements.py`, `subscriptions.py` middleware,
`views_operator.py`, `management/commands/cloudsneeker_operator.py`,
migration `0014_operator_console.py`, task `cloudsneeker-operator-daily`),
`ui/app/(operator)/operator/*`, and `ui/cloudsneeker/` (`actions/operator.ts`,
`actions/entitlements.ts`, `lib/entitlements.ts`, `lib/operator.ts`,
`lib/plan-store.ts`, operator and plan components). Upstream hooks are listed
in [Upstream Hooks](upstream-hooks.md).

### Bootstrap the first operator

There are no default operator accounts. The user must already exist (sign up
or accept an invitation first), then an owner is granted from the API
container:

```bash
python manage.py cloudsneeker_operator grant you@company.com --role owner
python manage.py cloudsneeker_operator list
python manage.py cloudsneeker_operator revoke someone@company.com
```

On ECS, run it as a one-off task of the API task definition (same cluster,
subnets and security group as the API service; the API image's working
directory is the Django project):

```powershell
aws ecs run-task --profile kscnexus --region us-east-1 `
  --cluster <cluster> --task-definition <api-task-definition> `
  --launch-type FARGATE `
  --network-configuration "awsvpcConfiguration={subnets=[<private-subnet>],securityGroups=[<api-sg>],assignPublicIp=DISABLED}" `
  --overrides '{"containerOverrides":[{"name":"<api-container>","command":["python","manage.py","cloudsneeker_operator","grant","you@company.com","--role","owner"]}]}'
```

Check the task's CloudWatch log for "is an operator with role owner", then
sign in again: the sidebar shows **Operator console** under Organization and
`/operator` opens. Every grant and revoke is in the operator audit log with
the actor `cli`.

### What was built

* Tables (not row-level security protected, read through the admin
  connection): `cloudsneeker_platform_operators`, `cloudsneeker_plans`,
  `cloudsneeker_subscriptions`, `cloudsneeker_subscription_events`,
  `cloudsneeker_usage_snapshots`, `cloudsneeker_operator_audit_events`. The
  tenant database user only has SELECT and DELETE on the tables that point at
  a tenant or user, so deleting either still cascades.
* The migration seeds the plans below and gives every existing tenant an
  active `legacy` subscription. A tenant created later gets a subscription on
  first use, on `CLOUDSNEEKER_DEFAULT_PLAN` (default `legacy`, so nothing
  changes until the owner picks another default).
* `GET /api/v1/entitlements`: plan, status, effective status, read-only flag,
  features, limits, usage, over-limit keys, dates. Cached 60 seconds per
  tenant; operator changes invalidate the cache of the API process that made
  them (other processes catch up within the cache time).
* Enforcement (`SubscriptionEnforcementMiddleware`, before the view, headers
  only, fails open): `subscription_inactive` for writes while `suspended`,
  `expired` (including an end date that passed before the daily task ran) or
  `cancelled` (sign-in, token refresh and switch, `/entitlements`, the
  user's own `PATCH /users/<id>`, invitation accept and the operator API stay
  open); `feature_not_in_plan` for paths of a missing feature (attack paths,
  compliance overviews, application security, governance, reports, report
  schedules, assistant, finding triage, audit log, integrations, SAML, API
  keys, and any API-key request without `api_access`); `plan_limit_reached`
  on create of providers, invitations (members plus pending invitations count
  against users), application security targets and report schedules. All are
  JSON:API 403 errors with `meta`.
* Operator API (`CLOUDSNEEKER_OPERATOR_ENABLED=false` turns it off; non
  operators and API keys get 404): `operator/me`, `operator/tenants` (filters
  search, status, plan, expiring_within_days, over_limit; `meta.summary`),
  `operator/tenants/{id}`, `operator/tenants/{id}/usage-snapshots`,
  `operator/subscriptions/{tenant_id}` (GET, PATCH), `operator/plans` and
  `operator/plans/{code}` (CRUD; legacy, the default plan and plans in use
  cannot be deleted), `operator/operators` (owner), `operator/audit-events`.
  Roles: every role reads; `owner` and `billing` change subscriptions and
  plans; only `owner` sets `suspended` or `cancelled` and lists operators.
  A subscription change writes a `SubscriptionEvent`, an `OperatorAuditEvent`
  (field names only) and `operator.subscription_update` in the customer's own
  audit log. Operator requests are not written to the operator's own tenant
  audit log.
* Daily task `cloudsneeker-operator-daily` (Celery beat, registered by the
  migration): expires subscriptions whose `ends_at` (or trial end) passed and
  writes one `UsageSnapshot` per tenant and day.
* UI: `/operator` overview, `/operator/customers` (filters in the URL),
  `/operator/customers/[tenantId]` (subscription editor with feature toggles
  and limit overrides, usage bars, daily usage, members, recent scans,
  history), `/operator/plans`, `/operator/audit`. Tenant app: sidebar hides
  features outside the plan, a banner for read-only subscriptions and plans
  ending within 7 days, and a plan card on the profile page.

Known gaps: assistant requests are not counted yet (reported as not
tracked); scans per month and assistant requests are shown but not enforced;
SAST is a feature key but application security targets are gated as a whole;
the entitlement cache is per process (no shared cache is configured); no
MFA or IP allow-list on the operator routes yet (WAF rule and EB-008 below);
scheduled jobs (scan, report and application security schedules run by
Celery beat) are not paused for read-only tenants, only API writes are
refused; operators are granted only from the command line (no console page
to grant roles).

### Design

Data (Cloudsneeker app, non-RLS operator tables plus a per-tenant snapshot):

- `Plan`: `code`, `name`, `features` (list), `limits` (providers, users,
  application security targets, scans per month, report schedules, Seeker AI
  requests per month), `is_public`, `sort_order`.
- `Subscription` (one per tenant): plan, `status` (`trial`, `active`,
  `past_due`, `suspended`, `expired`, `cancelled`), `starts_at`, `ends_at`,
  `trial_ends_at`, `seats`, `feature_overrides`, `limit_overrides`,
  `billing_source` (`manual`, `aws_marketplace`, `azure_marketplace`,
  `self_hosted_licence`), `external_customer_id`, notes.
- `SubscriptionEvent`: history of plan, status and date changes.
- `UsageSnapshot`: daily per-tenant counts computed from existing tables
  (providers, users, scans this month, findings, application security
  targets, reports generated, Seeker AI calls).

Feature keys: `cloud_posture`, `attack_paths`, `compliance`,
`application_security`, `sast`, `governance`, `reports`, `report_schedules`,
`seeker_ai`, `finding_triage`, `audit_log`, `sso`, `api_access`,
`integrations`.

Enforcement:

- `entitlements.for_tenant(tenant_id)` returns the effective features and
  limits (plan plus overrides), cached briefly.
- `GET /api/v1/entitlements` lets the UI hide navigation and show an upgrade
  prompt for features not in the plan.
- A DRF permission on Cloudsneeker viewsets refuses disabled features with a
  clear message. Upstream endpoints are gated by a Cloudsneeker middleware
  that maps paths to features, so upstream views stay untouched.
- Limits are checked when creating providers, users (invitations),
  application security targets and report schedules.
- `suspended` and `expired` tenants become read-only: sign-in works, mutating
  requests return a clear "subscription inactive" error, and the UI shows a
  banner.
- Existing tenants are migrated to a "Legacy (unlimited)" plan so nothing
  changes for them.

Operator UI: customer list (plan, status, expiry, usage against limits,
last activity), customer detail (subscription editor, feature toggles, limit
overrides, usage chart, members, recent scans, subscription history), plan
catalogue editor, expiring-soon and over-limit views.

## Phase 2: Platform status, upgrades and alerts

- Version panel: running image tag per service, last deploy time, CI status of
  that commit, pending migrations.
- Health: ECS desired vs running tasks per service, recent task stops, RDS and
  cache status (read-only IAM `ecs:Describe*`, `rds:Describe*`,
  `cloudwatch:GetMetricData` on the task role; infra change through
  `deploy.ps1`).
- Workload: Celery queue depth, scans running or stuck, scan failure rate,
  Application Security and governance run failures, report failures.
- API: request rate, 4xx/5xx rates and latency from load balancer metrics;
  WAF blocks, including sign-in rate-limit hits.
- Alerts (EB-005): CloudWatch alarms to an SNS topic (email and Slack) for
  5xx rate, unhealthy targets, task crash loops, RDS CPU and storage, queue
  backlog, certificate expiry. Alarm states are shown in the console.

## Phase 3: Observability

- Logs: JSON logs already go to CloudWatch; add saved Logs Insights queries
  (errors by endpoint, slow requests, failed sign-ins) and 30 to 90 day
  retention.
- Metrics: CloudWatch Container Insights for ECS; application metrics through
  CloudWatch Embedded Metric Format (scans per hour, findings ingested, report
  generation time).
- Traces: OpenTelemetry for Django and Celery through the AWS Distro for
  OpenTelemetry collector as a sidecar, exported to X-Ray. Upstream already
  supports Sentry for errors; set `SENTRY_DSN` to use it.
- Synthetic checks: a CloudWatch Synthetics canary signs in with a dedicated
  monitoring account every 5 minutes and opens Overview (needs a
  monitoring-only user created by the owner).
- Public status page on `status.kscnexus.com` fed by the canary (EB-037).
- Dashboards as code in the CloudFormation template.

## Phase 4: Customer-environment deployment

Delivery options:

| Option | Packaging | Fits |
| --- | --- | --- |
| Single-tenant in the customer's AWS account | The existing ECS CloudFormation stack (`cloudsneeker/deploy/ecs/`), parameterised for the customer's VPC, domain and certificate | Regulated customers that refuse SaaS |
| Kubernetes (EKS, AKS, GKE, on-premises) | The Helm chart in `cloudsneeker/deploy/helm/cloudsneeker-app` | Customers with a platform team |
| Azure | Azure Managed Application (Bicep) running the same containers on AKS or Container Apps | Azure Marketplace buyers |

Requirements for a customer install:

- Licence file: a signed token (Ed25519) holding customer, plan, features,
  limits and expiry. The app checks it offline with an embedded public key;
  no call home is needed. Grace period after expiry, then read-only.
- Images: published to a customer-pull registry, signed (cosign), with an
  SBOM and a vulnerability report per release. Semantic versions and release
  notes (EB-049).
- Upgrades: the customer runs the same stack or chart update with a new tag;
  database migrations run on start. Supported N-1 upgrade path and a rollback
  runbook.
- Optional usage report: a monthly signed usage file, or opt-in telemetry, for
  metered contracts.
- Hardening defaults: private subnets, HTTPS only, encrypted storage,
  customer-managed KMS keys optional, no outbound access except the cloud APIs
  being scanned and the vulnerability DB mirror (an offline DB bundle for
  air-gapped sites).

## Selling on AWS and Azure marketplaces

AWS Marketplace:

1. Register as a seller (legal entity, bank account, tax forms) and accept the
   seller terms: owner task.
2. SaaS product (for the hosted service):
   - Pricing: contract (annual tiers matching the plans) and/or usage
     dimensions (for example providers per month).
   - Integration: a registration landing page that resolves the marketplace
     token (`ResolveCustomer`), creates or links a tenant and a
     `Subscription` with `billing_source=aws_marketplace`; an SQS/SNS
     subscriber for subscribe, unsubscribe and entitlement-updated events;
     `GetEntitlements` for contracts; `BatchMeterUsage` hourly for metered
     dimensions.
3. Container product (for customer installs): images scanned by AWS, a
   deployment template, and AWS License Manager or the metering API for
   entitlement checks.
4. Listing review: EULA, support terms, security questionnaire, architecture
   description.

Azure Marketplace:

1. Partner Center account and publisher verification: owner task.
2. SaaS offer: plans in Partner Center, a landing page that resolves the
   purchase token through the SaaS Fulfillment API v2 (`resolve`, then
   `activate`), a webhook for change-plan, suspend, reinstate and unsubscribe,
   and the metered billing API for usage dimensions. Requires a Microsoft
   Entra ID app registration for the publisher API.
3. Managed Application (for installs into the customer's subscription) built
   from Bicep templates.

Both marketplaces map onto the Phase 1 `Subscription` model, so the console
shows marketplace and direct customers the same way.

## Security of the business platform

- Identity: MFA for all users and mandatory for operators (EB-008), SSO for
  customers (SAML hardening EB-009, OIDC EB-028), close open sign-up
  (EB-002) once marketplace and invitation onboarding exist.
- Network: HTTPS only (done), WAF managed rules and sign-in rate limit
  (done), operator IP allow-list, HSTS (EB-015).
- Data: encryption at rest (RDS, EFS, S3), encrypted credentials (in place),
  encryption key rotation (EB-016), backups with a tested restore (EB-030),
  retention and deletion per contract (EB-025).
- Supply chain: pinned engine versions, CI image vulnerability gate (EB-017),
  signed images and SBOMs for customer installs, Dependabot-style dependency
  updates weekly.
- Detection: audit log (done), operator audit log, CloudTrail and GuardDuty on
  the hosting account, alarms (Phase 2).
- Assurance: external penetration test and SOC 2 readiness (EB-013) before
  large enterprise deals; a security page and `security.txt` (website).
- Keeping current: the cadence in
  [Keeping Security Content Current](security-content-updates.md), plus
  monthly patching of base images and quarterly access reviews of operators.

## Owner decisions needed

- Plan names, feature bundles and limits for Starter, Professional,
  Enterprise and Managed (defaults are proposed in Phase 1 and editable in the
  console).
- Which operator accounts exist, and the office/VPN IP ranges for the
  allow-list.
- Marketplace seller registration (AWS, Microsoft), pricing, EULA and support
  terms.
- Whether open self sign-up stays (trials) or onboarding is invitation and
  marketplace only.
