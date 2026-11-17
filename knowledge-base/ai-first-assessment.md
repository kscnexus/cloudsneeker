# AI-Firstify Assessment Report

**Project:** Cloudsneeker
**Date:** 2026-11-17
**Mode:** Re-engineer

Cloudsneeker is a multi-tenant security product sold to customers: cloud posture, application security and governance on one platform, built on Prowler. The assessment rubric was written for personal tools, where a web app, a database, sign-in and a deployment count against a project. Here they are the product, so dimensions 2 and 4 are judged on whether each part serves a customer. Nothing was removed on the rubric's say-so.

Scores show the state found, then the state after this change.

## Overall Score

| Dimension | Score | Summary |
|-----------|-------|---------|
| 1. Project Structure | YELLOW, now GREEN | Git, `.gitignore`, `AGENTS.md` and a 26-page knowledge base exist. The Cloudsneeker operating rules lived in an untracked `.cursor/rules/` folder, so a fresh clone or a worktree had none of them |
| 2. Agent Architecture | YELLOW | The product embeds an assistant (Seeker AI) and an LLM policy drafter. Both are customer features, read-only or dry-run, and go through the MCP server. Kept |
| 3. Skill Usage | YELLOW, now GREEN | 38 upstream skills covered Prowler patterns. No skill covered a Cloudsneeker workflow. Four were added |
| 4. Scope & Complexity | YELLOW | 86 backlog items, 50 buildable, while billing, paid hosting and legal terms are missing. Breadth is ahead of the ability to sell |
| 5. Context Hygiene | YELLOW | Reference material is well separated. Two dead links and rules that described a retired deployment were fixed. Root `AGENTS.md` is 227 lines, mostly one generated table |
| 6. Safety | YELLOW | Drafted policies cannot act, sign-up is closed, images are CVE-gated. A root `.env` is tracked, plan enforcement fails open, and the MCP server exposes upstream write tools |
| 7. Workflow Design | YELLOW | CI, pull requests and automatic deploys were in place. The written procedure pointed at CodeCommit and ECS, both gone. It is now three prescriptive skills with two validators, which CI does not run yet |

## Priority Recommendations

1. **[HIGH]** Decide paid hosting before the current cloud credit ends (EB-011). One VM without a standby holds every tenant: owner decision, then about a week.
2. **[HIGH]** Settle prices, a payment provider and the customer legal pack (EB-018, EB-079, EB-012). The entitlement engine is ready and has nothing to bill through: owner decisions.
3. **[HIGH]** Enforce the monthly scan and assistant limits plans already state (EB-080): up to 2 days.
4. **[HIGH]** Verify the nine "Done (pending deploy)" items signed in on the current site, MFA and SAML first: 1 day with an owner account.
5. **[HIGH]** Review the tracked root `.env`. It is the upstream development file, and its history shows only upstream commits, but it could not be opened in this review. Confirm it holds no deployed value: 15 minutes.
6. **[MEDIUM]** Publish the full API schema and add MCP tools for triage, reports, alerts, inventory and audit (EB-082, EB-081). This is what makes the product usable by a customer's own agents: about 2 weeks.
7. **[MEDIUM]** Decide whether an MCP client with an ordinary API key should reach the upstream write tools (delete provider, set user role, trigger scan). Today the caller's role is the only limit: owner decision, then 2 days.
8. **[MEDIUM]** Make plan enforcement fail closed for the lapsed-subscription check, keeping fail open only for tenants with no subscription row: 1 day.
9. **[MEDIUM]** Add guided onboarding, retention, data export, webhooks and Teams (Phase 1 of the launch plan): about 6 weeks.
10. **[LOW]** Stop new Phase 4 coverage items until Phase 1 and Phase 2 are done.
11. **[LOW]** Run the two validators in "Cloudsneeker: Tests" so a broken backlog row or an unrecorded upstream edit fails a pull request: half a day.
12. **[LOW]** Fix `skill-sync` for `ui/AGENTS.md` and `api/AGENTS.md`: the script reports success and writes nothing for those two files on Windows.

## Detailed Findings

### Dimension 1: Project Structure

Good: git with 165 commits in the last two weeks through pull requests; a `.gitignore` that excludes component `.env` files and assistant folders; a root `AGENTS.md` plus one per component; `knowledge-base/` as the internal map; Cloudsneeker code held in its own directories so upstream merges stay small.

Needs work: eight rule files in `.cursor/rules/` carried the working rules (placement, upstream split, verification, deploy). `.cursor/` is ignored by git, so the rules existed in one checkout only. `knowledge-base/README.md` and `feature-verification.md` linked to them. `CLAUDE.md` and `.claude/skills` are links created by `skills/setup.sh` and are not committed, so on Windows worktrees an assistant sees `AGENTS.md` but cannot load a skill by name.

### Dimension 2: Agent Architecture

Seeker AI (`ui/lib/lighthouse-v1/`, upstream) is a LangChain agent that reads data only through the MCP server with the user's token and an allowlist of read tools. `services/custodian_ai.py` drafts governance policies with the tenant's own model key; it strips `actions`, `mode` and `notify`, validates the draft three ways and never saves or runs it. `llm_compat.py` is a compatibility shim. None of this is a home-built agent framework, and all of it is something a customer uses. No de-agentification was done.

The gap is reach, not design. The MCP server has five Cloudsneeker tools (area findings, posture summary, one application finding, application overview, governance policies). About 25 route groups have none: triage, reports, alerts, application inventory, SBOMs, governance runs, audit events, search. The assistant has no page context for Cloudsneeker pages. The checked-in OpenAPI file has no Cloudsneeker routes, 13 endpoints are excluded from the served schema, and there is no `llms.txt`.

### Dimension 3: Skill Usage

`skills/` follows the upstream format: frontmatter with `scope` and `auto_invoke`, synced into `AGENTS.md` by `skill-sync`. All 38 skills described Prowler. The repeated Cloudsneeker workflows (place a feature, record a hook, pass the brand gate, ship and verify live, work a backlog item, merge upstream) were spread over the untracked rules, the knowledge base and session memory.

### Dimension 4: Scope & Complexity

The web app, database, sign-in, multi-tenancy and deployment are the product and stay. The concern is sequence. The backlog grew by 28 competitor-parity items on 2026-11-10 (runtime sensor, DSPM, CIEM, IDE plugin, Terraform provider) while a customer still cannot pay, reset a password or be onboarded without the operator. The entitlement engine is solid: `SubscriptionEnforcementMiddleware` gates 12 feature areas and four count limits. It is ahead of the commercial side around it.

### Dimension 5: Context Hygiene

The knowledge base uses progressive disclosure well: a 29-line index over focused pages. Problems found: two links to files that are not in the repository; nine backlog items still marked "Done (pending deploy)" because nobody has verified them on the current deployment; EB-001 marked Done although its domain is gone; a deploy rule naming a CodeCommit remote and an ECS stack retired on 2026-11-03; no single page ordering the backlog. Root `AGENTS.md` is over the rubric's 200 lines because of the generated auto-invoke table.

### Dimension 6: Safety

Good: sign-up closed by flag, sign-in lockout, MFA, signed SAML, key rotation, an audit log, an image CVE gate in CI, generated policies that cannot act, a live probe that never signs in.

Open:

- Root `.env` is tracked. `git log -- .env` shows only upstream release commits, so it should hold upstream development defaults. Reading it was blocked during this review, so that is not confirmed.
- The repository is public and names the deployed hosts. That was a deliberate choice for the hosting plan; it makes the `.env` check matter more.
- Plan enforcement lets a request through on any internal error.
- The MCP server mounts upstream write tools (create and delete integrations, delete providers, set user role, trigger scans). Seeker AI's allowlist excludes them; an outside MCP client with an API key does not have that allowlist.
- MFA and SAML were not exercised against a real account or identity provider on the current deployment.

### Dimension 7: Workflow Design

Good: "Cloudsneeker: Tests" on every pull request, deploy after tests pass, an uptime probe, a rollback page, conventional commits. Missing before this change: a current written procedure, a check that an upstream file was not edited without a recorded hook, a check that the backlog table stays valid, and a review step separate from the author.

## Changes Made (Re-engineer mode only)

| Action | File | Description |
|--------|------|-------------|
| Created | `skills/cloudsneeker-feature/SKILL.md` | Placement, upstream hooks and brand gate, ported from four untracked rule files |
| Created | `skills/cloudsneeker-feature/assets/check_upstream_edits.py` | Lists modified upstream files that `upstream-hooks.md` does not record |
| Created | `skills/cloudsneeker-ship/SKILL.md` | Current release path (GitHub, CI, Vercel, Azure), live verification, rollback |
| Created | `skills/cloudsneeker-backlog/SKILL.md` | One backlog item from pick to verified release, with a sub-agent review step |
| Created | `skills/cloudsneeker-backlog/assets/validate_backlog.py` | Validates the backlog table and the launch plan's references |
| Created | `skills/cloudsneeker-upstream-sync/SKILL.md` | Merge procedure pointing at `upstream-sync.md` |
| Created | `knowledge-base/saas-launch-plan.md` | Open items ordered into five phases, owner decisions first |
| Created | `knowledge-base/ai-first-assessment.md` | This report |
| Modified | `AGENTS.md` | Cloudsneeker skills table, how to load a skill that is not listed, the ship rule, regenerated auto-invoke rows |
| Modified | `knowledge-base/enterprise-backlog.md` | EB-001 reopened; EB-079 to EB-086 added |
| Modified | `knowledge-base/README.md`, `feature-verification.md` | Dead links replaced; three pages added to the index |
| Modified | `knowledge-base/upstream-hooks.md` | `AGENTS.md` recorded as a hooked file |

No application code, migration, workflow or deployment file was changed. Nothing was deleted.

## Still Needs Human Decision

- [ ] Paid hosting and a standby for the backend and database (EB-011)
- [ ] Product domain (EB-001 was met on the closed AWS account)
- [ ] Prices, plan contents and a payment provider (EB-018, EB-079)
- [ ] Customer legal pack (EB-012)
- [ ] Sender domain for platform email (EB-029)
- [ ] Whether outside MCP clients may use write tools
- [ ] Confirm the tracked root `.env` holds only development defaults
- [ ] Whether to commit the eight `.cursor/rules/` files or delete them now that the skills replace them. They still describe the retired deployment

## Recommended Next Steps

1. Take the Phase 0 decisions in [`saas-launch-plan.md`](saas-launch-plan.md), hosting first.
2. Work Phase 1 one item at a time with `skills/cloudsneeker-backlog/SKILL.md`, starting with EB-080.
3. Work Phase 2 (EB-082, EB-081, EB-084) so customers' agents and Seeker AI reach every module.
4. Run `skills/setup.sh --claude` on a machine that can create links, or rely on the `AGENTS.md` skill table.
