# Enterprise Readiness Assessment

Assessed 2026-10-30 against `main` (`082c58e8e`). Every status below was checked in code; items marked "unverified" were not provable from the repository. The work list that follows from this page is [`enterprise-backlog.md`](enterprise-backlog.md).

## Executive Summary

Cloudsneeker is a credible **agentless CSPM + compliance platform with an ASPM add-on**. Its scanning breadth is enterprise-grade because it inherits Prowler's check catalog (20+ providers under `prowler/providers/`, 40+ AWS frameworks under `prowler/compliance/aws/`) and adds application security (Trivy, OpenGrep SAST), Cloud Custodian governance in dry-run, a reporting suite, and an AI assistant. Tenant isolation is solid: every model is PostgreSQL row-level-security protected (`RowLevelSecurityProtectedModel` in `api/src/backend/api/models.py`).

Against category leaders (Wiz, Orca, Prisma Cloud, Lacework, Snyk), it is behind in three areas buyers check first:

1. **Trust of the hosted service.** The public endpoint is plain HTTP, sign-up is open to anyone, login is not throttled, there is no user-action audit log, and the stack runs single-instance in one region. A security vendor's security review fails today.
2. **Workflow depth.** Findings can be muted, but there is no triage status, owner, SLA, expiring risk acceptance, or two-way ticket sync. Leaders sell remediation workflow, not finding lists.
3. **Risk context.** Attack Paths and ThreatScore exist, but vulnerabilities carry no EPSS or CISA KEV signal, and there is no business-context weighting or runtime/agentless workload (VM disk) scanning.

Where it wins: price, transparency (open check logic and frameworks), breadth of compliance frameworks, self-hostable deployment, and a consultancy can wrap it in services. Position it as **"assessment-grade CSPM + compliance evidence, delivered with experts"**, not as a Wiz replacement. Close the P0 items in the backlog before any enterprise pilot on the hosted site.

## Capability Matrix

Status: **Have** (shipped and usable), **Partial** (exists with material gaps), **Missing**.

### Identity and Access

| Capability | Status | Evidence and gap |
| --- | --- | --- |
| SSO SAML | Partial | `SAMLConfiguration`, `SAMLDomainIndex` in `api/models.py`; `config/settings/social_login.py`. SP does not sign AuthnRequests, `want_assertion_signed` is commented out (upstream TODO), `reject_idp_initiated_sso: False`. Strictness of IdP signature validation unverified. |
| SSO OIDC | Partial | Google and GitHub social login only (`social_login.py`). No generic OIDC (Okta/Entra/Auth0 via OIDC). |
| SCIM provisioning | Missing | No `scim` anywhere in `api/src/backend`. |
| MFA | Missing | No TOTP/WebAuthn code. Only possible today by forcing SAML with IdP-side MFA. |
| Password policy | Have | `AUTH_PASSWORD_VALIDATORS` in `config/django/base.py`. |
| Password reset / email verification | Missing (self-hosted) | `ui/proxy.ts` keeps `/reset-password`, `/email-verification` commented "In Cloud uncomment". |
| Self sign-up control | Missing | `UserViewSet.get_permissions` returns `AllowAny` for `create` (`api/v1/views.py`); no flag to close sign-up. Anyone reaching the URL creates a tenant. |
| Login brute-force protection | Partial | `token-obtain` throttle defaults to `None` (`base.py`), and `platform.yaml` does not set `DJANGO_THROTTLE_TOKEN_OBTAIN`. WAF has no rate-based rule. |
| RBAC | Partial | `Role` with 7 coarse flags (`manage_users`, `manage_account`, `manage_billing`, `manage_providers`, `manage_integrations`, `manage_scans`, `unlimited_visibility`) plus provider-group visibility (`api/rbac/permissions.py`). No read-only auditor preset, no per-feature scopes (reports vs scans vs governance), no custom permission sets. |
| API keys | Have | `TenantAPIKey` (prefixed, hashed, tenant RLS) in `api/models.py`, `api/authentication.py`; docs `cloudsneeker/docs/admin/api-keys.mdx`. Scope is the user's role; no per-key scopes (unverified). |
| Session tokens | Have | JWT 30 min access, 24 h refresh, rotation + blacklist (`SIMPLE_JWT` in `base.py`). |

### Multi-Tenancy and MSSP

| Capability | Status | Evidence and gap |
| --- | --- | --- |
| Per-client isolation | Have | Postgres RLS on every table; Cloudsneeker models extend `CloudsneekerRLSModel` (`cloudsneeker_api/models.py`). |
| Users in several tenants | Have | `Membership` (owner/member) and `tokens/switch` (`api/v1/urls.py`). |
| Org hierarchy (MSSP parent over client tenants) | Missing | No parent tenant, no cross-tenant roll-up dashboard, no delegated admin. Consultant must switch tenant per client. |
| White-label per client | Missing | Brand is frozen at build time (`cloudsneeker/brand.py`, `ui/cloudsneeker/brand.ts`). Reports carry Cloudsneeker branding only; no per-tenant logo or report cover. |
| Cloud org onboarding (AWS Orgs / Azure MG / GCP org) | Partial | Provider groups exist; bulk org onboarding is on the roadmap, not built (unverified beyond memory notes). |

### Audit and Accountability

| Capability | Status | Evidence and gap |
| --- | --- | --- |
| User-action audit log | Missing | No audit model or middleware. Only `created_by` on some rows (`MuteRule`) and CloudWatch app logs. |
| Audit export / SIEM stream of admin events | Missing | Nothing to export. |
| Infra audit | Partial | VPC flow logs (14 days), ALB access logs to S3, RDS Postgres logs (`platform.yaml`). CloudTrail is account-level and not managed by the stack (unverified). |

### Data Protection

| Capability | Status | Evidence and gap |
| --- | --- | --- |
| Encryption at rest | Have | RDS `StorageEncrypted`, Valkey `AtRestEncryptionEnabled`, EFS `Encrypted`, ECR AES256 (`platform.yaml`, `registry.yaml`). All AWS-managed keys, no customer-managed KMS. |
| Encryption in transit (internal) | Have | `rds.force_ssl: 1`, Valkey `TransitEncryptionEnabled` + auth token. UI to API inside the VPC is plain HTTP on Cloud Map (`UI_API_BASE_URL`). |
| Encryption in transit (public) | Missing | ALB HTTP listener only until `DomainName` + `CertificateArn` are set; the HTTPS path (TLS 1.3 policy, HTTP->HTTPS redirect) is already templated. |
| Secrets handling | Have | Cloud credentials Fernet-encrypted in `ProviderSecret` / `Integration._credentials` (`FERNET_SECRET` in `base.py`); platform secrets in Secrets Manager; RDS master password managed by RDS. Git tokens redacted (`cloudsneeker/git_auth.py`). |
| Key management / rotation | Partial | Single Fernet key from env; no documented rotation procedure or MultiFernet. |
| Data retention / deletion | Partial | Tenant and user delete exist (`TenantViewSet.destroy`, `UserViewSet.destroy`). No configurable retention for findings, scans, report artifacts, or EFS files. |
| Data residency | Partial | Single region `us-east-1`; no EU option. |
| LLM data egress | Partial | Seeker AI sends finding context to the tenant's configured LLM provider (`LighthouseConfiguration`). Needs a DPA statement and an opt-out per tenant (exists by not configuring; not documented for buyers). |

### Platform Security of Our Deployment

| Capability | Status | Evidence and gap |
| --- | --- | --- |
| TLS on public endpoint | Missing | Blocked on domain and ACM certificate. |
| WAF | Partial | WebACL with `AWSManagedRulesCommonRuleSet` and `KnownBadInputs`. No rate-based rule, no IP reputation / anonymous IP list, no geo or bot control. |
| Private subnets | Have | All services `AssignPublicIp: DISABLED`; RDS `PubliclyAccessible: false`; VPC endpoints for ECR, logs, Secrets Manager. |
| Least-privilege IAM | Partial | Execution role scoped to the app secret. Task role grants `sts:AssumeRole` on `Resource: "*"` (registry-scanning policy) with no condition; ECR read is account-wide. GitHub OIDC role scoped to immutable repo subject (`registry.yaml`). |
| Image scanning / supply chain | Partial | ECR `ScanOnPush`, `IMMUTABLE` tags, sha256-pinned OpenGrep and Trivy downloads. No CI gate that fails on critical CVEs in `cloudsneeker-images.yml`, no image signing or SBOM attestation. |
| Backups / DR | Partial | RDS `BackupRetentionPeriod: 1`, `DeletionProtection`, `DeletionPolicy: Retain`; EFS backup enabled. No cross-region copy, no restore runbook or tested RTO/RPO. Neo4j (Attack Paths) durability unverified. |
| High availability | Partial | Two AZs. RDS single-AZ by default (`DatabaseMultiAz: false`), Valkey `MultiAZEnabled: false`, API desired 1 (autoscale 1–4), worker, beat, MCP, Neo4j at 1. UI at 2. |
| Monitoring and alerting | Partial | Container Insights, 30-day log groups, health checks. No `AWS::CloudWatch::Alarm`, no on-call paging, no uptime probe. |
| Rate limiting | Partial | DRF throttles for attack-path queries, health, shared reports (`SharedReportThrottle`, `views_reports.py`); login unthrottled. |
| Security headers | Have | API: nosniff, `X_FRAME_OPTIONS = DENY`, referrer policy, secure cookies (`base.py`). UI: CSP built per request (`ui/proxy.ts`, tested in `ui/next.config.test.ts`). HSTS absent until HTTPS. |
| Vulnerability disclosure | Partial | `SECURITY.md` is still the upstream Prowler text; needs a Cloudsneeker contact and policy. |

### Coverage

| Domain | Status | Evidence |
| --- | --- | --- |
| CSPM | Have | Prowler checks across AWS, Azure, GCP, Kubernetes, M365, GitHub, Google Workspace, Okta, OCI, Alibaba, Cloudflare, MongoDB Atlas and more (`prowler/providers/`). |
| CIEM | Partial | IAM / Entra checks and Attack Paths privilege-escalation queries (`api/attack_paths/queries/aws.py`). No effective-permissions graph across clouds or unused-permission right-sizing. |
| CWPP / agentless vuln | Partial | Container image scanning (Trivy `image` mode), K8s cluster scan (`k8s` mode), AWS Inspector/GuardDuty enablement checks. No agentless VM disk snapshot scanning, no runtime agent. |
| KSPM | Have | Kubernetes provider plus Trivy `k8s` mode. |
| DSPM | Partial | Macie-enablement and storage exposure checks only; no data classification of buckets/databases. |
| ASPM: SCA | Have | Trivy `fs`/`repo` modes into shared `Finding` rows (`services/trivy_import.py`). |
| ASPM: SAST | Have | OpenGrep + GitLab sast-rules (`services/sast.py`). |
| IaC | Have | Prowler `iac` provider and Trivy `iac` mode. |
| Secrets in code | Have | Trivy secret scanner (Secrets hub section). |
| SBOM | Have | Trivy `sbom` mode. |
| Container registry | Have | Private ECR via role/external ID (`cloudsneeker_api/ecr_auth.py`), image filters (`image_filters.py`). |
| DAST / API security | Missing | None. |

### Risk and Prioritization

| Capability | Status | Evidence and gap |
| --- | --- | --- |
| Risk scoring | Have | ThreatScore framework (`ThreatScoreSnapshot`), executive report score and grade (`cloudsneeker_api/reports/`). |
| Attack paths | Have | Cartography + Neo4j (`AttackPathsScan`, `tasks/jobs/attack_paths/`). AWS-centric. |
| EPSS / CISA KEV | Missing | No `epss` or `kev` in import or models. CVE findings rank by CVSS severity only. |
| Business context tagging | Partial | `ResourceTag` / provider groups exist; tags do not change priority. No "crown jewel" or environment weighting. |
| Toxic combinations across cloud + code | Missing | Cloud and AppSec findings share tables but are not correlated. |

### Workflow

| Capability | Status | Evidence and gap |
| --- | --- | --- |
| Finding triage status | Missing | Roadmap item 3, not started. `Finding` has `muted`, `delta`, `first_seen_at` only. |
| Exceptions / risk acceptance with expiry | Partial | `MuteRule` (name, reason, `created_by`, finding UIDs) and mutelist. No expiry, no approver, no re-review. |
| Assignment / ownership | Missing | No owner field or ownership rules. |
| SLA tracking | Missing | `first_seen_at` exists to compute age; no SLA policy or breach report. |
| Jira | Partial | One-way issue creation (`Jira.send_findings`, `prowler/lib/outputs/jira/jira.py`), grouped dispatch. No status sync back, no auto-close on fix. |
| ServiceNow | Missing | Not present. |
| Remediation guidance | Have | Check metadata remediation text, report "fix" and next actions. |
| Auto-remediation | Missing (by design) | Custodian is dry-run only. Guardrailed opt-in actions are a later product decision. |

### Integrations

| Capability | Status | Evidence |
| --- | --- | --- |
| Amazon S3, AWS Security Hub | Have | `Integration.IntegrationChoices` (`api/models.py`). |
| Slack, email alerts | Have | `AlertRule`, `SlackAppConfig`, `EmailDeliveryConfig` (`cloudsneeker_api/models.py`). |
| Microsoft Teams | Missing | Not present. |
| Generic webhooks | Missing | Not present. |
| SIEM (Splunk HEC, Sentinel, QRadar) | Missing | Only indirect via Security Hub or S3 OCSF export. |
| SOAR / PagerDuty | Missing | Not present. |
| Public API | Have | JSON:API under `/api/v1/`, OpenAPI docs at `/api/v1/docs`. |
| MCP server | Have | `mcp_server/`, internal only (not routed by the ALB). |

### Compliance and Reporting

| Capability | Status | Evidence |
| --- | --- | --- |
| Frameworks | Have | CIS, NIST 800-53/171/CSF, ISO 27001, SOC 2, PCI 4.0, HIPAA, GDPR, NIS2, DORA, FedRAMP, CMMC, CSA CCM, Essential Eight and more (`prowler/compliance/`). |
| Audit-ready reports | Have | 9 report types, branded PDF/XLSX/CSV, share links, schedules (`cloudsneeker_api/reports/`). |
| Trend | Have | `DailySeveritySummary`, report trend points, Multiple Scans comparison. |
| Evidence collection (manual controls, attachments, attestations) | Missing | Only automated check results; no upload of policy documents or control owner sign-off. |
| Cross-provider compliance roll-up | Missing | Roadmap item 4. |

### Operations

| Capability | Status | Evidence |
| --- | --- | --- |
| Scheduling | Have | `services/scan_schedule.py`, `trivy_schedule.py`, `custodian_schedule.py`, report schedules. |
| Scalability | Partial | Worker 4 vCPU / 30 GB single task; 8 vCPU account cap noted in deploy memory. No queue-depth autoscaling for workers. |
| Upgrade path | Have | Hook discipline (`knowledge-base/upstream-hooks.md`, `upstream-sync.md`), brand transform rules. |
| Release process | Partial | `cloudsneeker-release.yml`, `cloudsneeker-images.yml`; no published changelog or versioned release notes for customers. |

### Commercial Readiness

| Item | Status | Evidence and gap |
| --- | --- | --- |
| Prowler Apache-2.0 | Partial | `LICENSE` and `NOTICE` present; NOTICE disclaims affiliation and trademarks. Must keep upstream copyright headers and state changes (Apache 2.0 §4b). |
| OpenGrep (LGPL-2.1) | Partial | Used as an unmodified separate binary (`api.Dockerfile`) — compatible with commercial SaaS. Not listed in NOTICE; source offer not documented if images are ever distributed to customers. |
| GitLab sast-rules (MIT) | Partial | License file kept in the image (`api.Dockerfile`); not in NOTICE. Commons Clause and GitLab EE folders correctly excluded. |
| Cloud Custodian, Trivy (Apache-2.0) | Partial | Installed in the image; not attributed in NOTICE. |
| Third-party notices file | Missing | No `THIRD_PARTY_NOTICES`. Python/npm dependency licenses not inventoried. |
| Trademark | Partial | UI hides Prowler marks (brand modules, `brand_audit.py`). `SECURITY.md` still names Prowler; install-facing names (`prowlercloud/*` images, JWT defaults) remain by design. |
| Customer terms (MSA, DPA, SLA, privacy policy) | Missing | Owner decision. |

### Supportability

| Item | Status | Evidence |
| --- | --- | --- |
| Docs | Have | Mintlify site `cloudsneeker/docs/` (getting started, admin SSO/API keys/roles, integrations, generated check pages). |
| Onboarding | Partial | Empty states and "Build risk view" exist; no guided first-run wizard or per-cloud onboarding checklist (unverified). |
| In-app help | Partial | Docs links removed by brand direction; no in-app help panel. |
| Support SLAs, status page | Missing | Owner decision; no status page. |

## Top 10 Deal-Blocking Risks

1. **No HTTPS on the public endpoint.** Credentials and JWTs travel in clear text. Fails every security questionnaire. Needs a domain and ACM certificate (owner).
2. **Open self sign-up.** Anyone with the URL creates a tenant and can run scans and LLM calls on our account (`AllowAny` on user create).
3. **No login throttling or MFA.** Brute-force and credential stuffing are unmitigated for password users.
4. **No user-action audit log.** SOC 2 CC6/CC7 and ISO A.8.15 evidence cannot be produced for our own service.
5. **No SOC 2 / ISO attestation, DPA, or pen-test report for the hosted service.** Procurement stops here (owner).
6. **Single points of failure and thin backups.** Single-AZ RDS and Valkey, one API/worker task, 1-day backup retention, no alarms, no DR test.
7. **Workflow gap.** No triage, ownership, SLA, or expiring exceptions; one-way Jira. Security teams cannot run a programme on it.
8. **SAML hardening.** Unsigned AuthnRequests, IdP-initiated SSO accepted, no SCIM deprovisioning.
9. **Over-broad task role.** `sts:AssumeRole` on `*` from the API/worker role means a compromised task can try any role in any account that trusts it; this is the role customers grant into their accounts.
10. **Third-party license notices incomplete.** OpenGrep, GitLab rules, Custodian and Trivy are missing from NOTICE; a buyer's legal review will flag it.

## Recommended Positioning for the Consultancy

Sell **outcomes delivered by experts, with the platform as the evidence engine**. Lead with services; the product makes them repeatable and sticky.

| Service | What the client buys | How Cloudsneeker supports it | Gaps to close first |
| --- | --- | --- | --- |
| Cloud Security Assessment (fixed-fee, 2–4 weeks) | Posture baseline, attack paths, prioritized fix plan, executive readout | Multi-cloud scans, Attack Paths, AppSec scans, Executive and Cloud posture PDF reports, CLI import for clients who will not grant access | EB-001 HTTPS, per-client report branding (EB-026), EPSS/KEV (EB-022) |
| Compliance Readiness (SOC 2, ISO 27001, PCI, HIPAA, NIS2/DORA) | Gap analysis, remediation roadmap, evidence pack for the auditor | 40+ frameworks, compliance reports, Multiple Scans comparison, scheduled reports | Evidence attachments and manual controls (EB-035), risk acceptance with expiry (EB-019) |
| Managed Cloud Security ("MDR-lite" / continuous posture) | Monthly posture review, triaged alerts, ticketed remediation, SLA reporting | Schedules, alerts (email/Slack), Jira, scheduled reports, Seeker AI for analyst speed | Triage and ownership (EB-010, EB-020), SLA tracking (EB-021), MSSP roll-up (EB-032), SIEM/webhooks (EB-033, EB-023) |
| Secure SDLC / AppSec program | SCA, SAST, IaC, secrets, SBOM on client repos | Application Security hub, SAST, SBOM, IaC | CI integration (PR comments, fail gates) is not built (EB-043) |
| Governance-as-code | Policy library, dry-run drift reports | Cloud Governance (Custodian dry-run) | Guardrailed auto-remediation is a later decision (EB-046) |

Do not claim: runtime protection, agentless VM vulnerability scanning, DSPM classification, DAST, or SOC 2 attestation for the hosted service, until the matching backlog items are done. Offer a **single-tenant deployment in the client's own AWS account** (the CloudFormation stack already supports it) to buyers who will not use a shared SaaS; this sidesteps several hosted-trust blockers.
