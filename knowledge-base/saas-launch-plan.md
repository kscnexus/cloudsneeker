# SaaS Launch Plan

This page orders the open items in [`enterprise-backlog.md`](enterprise-backlog.md) into the sequence that gets the hosted product to a paying customer. The backlog holds each item's acceptance criteria. This page holds only the order and the reason for it. Work one item at a time with `skills/cloudsneeker-backlog/SKILL.md`.

Reviewed 2026-11-17 against the code on `main`. The evidence is in [`ai-first-assessment.md`](ai-first-assessment.md).

## Where the Product Stands

| Area | State | Evidence |
| --- | --- | --- |
| Product modules | Built | Cloud Security, Application Security, Governance, Reports, Alerts, Triage, global search |
| Identity | Built | MFA, SAML, API keys, closed sign-up, sign-in lockout. No password reset, no email verification, no OIDC |
| Plans and entitlements | Mostly built | `SubscriptionEnforcementMiddleware` gates features, blocks writes on lapsed subscriptions, and caps providers, users, targets and report schedules. Monthly scan and assistant request limits are recorded but not enforced |
| Billing | Missing | No payment provider. An operator changes plans by hand |
| Tenant lifecycle | Partial | Operator suspension works. No self-serve export or deletion request |
| Onboarding | Partial | Upstream product tours only. No first-run checklist |
| Outbound integrations | Partial | Email, Slack, Jira, S3, Security Hub. No webhook, Teams or SIEM |
| AI surface | Partial | The MCP server and Seeker AI reach findings, posture and policies through five Cloudsneeker read tools. Triage, reports, alerts, inventory and audit are not reachable |
| Hosting | At risk | One backend VM on a time-limited cloud credit, one database VM, no standby |
| Commercial | Blocked on owner | No prices, no customer legal pack, no payment account, no product domain |

## Phase 0: Owner Decisions

Nothing below can be built around. Each one blocks a later phase.

| Order | Item | Decision needed | Blocks |
| --- | --- | --- | --- |
| 1 | EB-011 | Paid hosting for the backend and database before the current credit ends, with backups and a standby | Every customer |
| 2 | EB-001 | Product domain for the web app and the API. The earlier domain went with the closed AWS account | EB-029, EB-014, EB-037 |
| 3 | EB-018 | Prices and what each plan includes | EB-079, the pricing page |
| 4 | EB-079 | Payment provider and account | Self-serve revenue |
| 5 | EB-012 | Terms, privacy policy, data processing agreement, support terms | Any signed customer |
| 6 | EB-029 | Sender domain for platform email | Password reset, email verification |
| 7 | EB-014, EB-086 | Security contact address and a mailbox for website leads | Disclosure policy, lead capture |

Operator-led sales can start once items 1, 2 and 5 are settled. Self-serve sales also need items 3, 4 and 6.

Nine finished items are still `Done (pending deploy)`: EB-002, EB-004, EB-007, EB-008, EB-009, EB-010, EB-015, EB-016 and EB-019. Their code is on `main` and deploys automatically, but each was last verified on the retired AWS stack or never signed in. One signed-in pass on the current site closes them.

## Phase 1: Sell-Ready

Buildable now. Each closes a gap a first customer meets in the first week.

| Order | Item | Why now |
| --- | --- | --- |
| 1 | EB-080 Enforce metered plan limits | Plans already promise these limits; nothing stops overuse |
| 2 | EB-038 Guided onboarding | A new tenant lands on empty pages with no next step |
| 3 | EB-085 Operator console health panels | The operator cannot see a failing worker or a growing queue without SSH |
| 4 | EB-025 Data retention policies | Storage on a single VM grows without bound |
| 5 | EB-083 Tenant data export and deletion request | Privacy terms in EB-012 will promise both |
| 6 | EB-023 Signed outbound webhooks | The general way to connect anything not yet integrated |
| 7 | EB-024 Microsoft Teams alerts | The most asked-for alert destination after Slack |
| 8 | EB-027 Auditor role preset | Consultancy engagements hand read-only access to client auditors |

## Phase 2: AI-Ready

The product is AI-ready when an outside agent can do through the API and the MCP server what a person can do in the web app, with the same role checks.

| Order | Item | Why |
| --- | --- | --- |
| 1 | EB-082 Machine-readable API surface | An agent needs the schema before it can use a route |
| 2 | EB-081 MCP tools for every Cloudsneeker module | Opens triage, reports, alerts, inventory and audit to agents |
| 3 | EB-084 Seeker AI covers Cloudsneeker pages | The built-in assistant gains the same reach, with confirmation before writes |

## Phase 3: Enterprise Evaluation

Buildable items a security team asks about during a trial. Order follows dependencies.

| Order | Item |
| --- | --- |
| 1 | EB-020 Finding ownership and assignment rules |
| 2 | EB-021 SLA policies and breach reporting |
| 3 | EB-028 Generic OIDC SSO |
| 4 | EB-026 Per-tenant report branding |
| 5 | EB-051 Toxic combinations across cloud and code |
| 6 | EB-052 Custom compliance frameworks |
| 7 | EB-035 Evidence collection and manual controls |
| 8 | EB-031 Two-way Jira sync |
| 9 | EB-030 Restore runbook and DR drill (after EB-011) |
| 10 | EB-034 SCIM 2.0 provisioning |
| 11 | EB-033 SIEM connectors (after EB-023) |
| 12 | EB-032 MSSP parent tenant and roll-up (after EB-026) |

## Phase 4: Differentiators

Every remaining `P2` item. Pick by customer demand, not by list order. Do not start one while a Phase 1 or Phase 2 item is open.

## Keeping This Page Current

Remove a row when its item is `Done`. Add a row when a new backlog item belongs in Phase 0 to 3. `python skills/cloudsneeker-backlog/assets/validate_backlog.py` fails when this page names an item the backlog does not have.
