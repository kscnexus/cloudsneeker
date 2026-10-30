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

## Phase 1: Customers, plans, licences, usage (building now)

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
