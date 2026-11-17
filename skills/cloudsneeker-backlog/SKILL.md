---
name: cloudsneeker-backlog
description: >
  Works one enterprise backlog item (EB-###) from pick to verified release, and keeps the backlog table valid.
  Trigger: When asked to work the backlog, pick the next item, add or re-prioritise backlog items, or update an item's status.
license: Apache-2.0
metadata:
  author: cloudsneeker
  version: "1.0"
  scope: [root]
  auto_invoke:
    - "Working an enterprise backlog item (EB-###)"
    - "Adding, re-prioritising, or closing backlog items"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

## Critical Rules

- One item per branch and pull request. Finish it before starting the next.
- NEVER start an item whose Owner is `Blocked: needs owner`. List it for the owner instead.
- NEVER mark an item `Done` before it is verified on the deployed site. Use `Done (pending deploy)` until then.
- NEVER invent customers, certifications, prices, or legal text to close a commercial item.
- The acceptance criteria are the scope. Do not add features the row does not ask for.

## Files

| File | Purpose |
| --- | --- |
| `knowledge-base/enterprise-backlog.md` | The backlog table: one row per item |
| `knowledge-base/saas-launch-plan.md` | The order items ship in for the hosted launch |
| `knowledge-base/enterprise-readiness.md` | The assessment the items came from |

## Steps

1. **Pick.** Take the first row in `saas-launch-plan.md` that is `Todo`, `Buildable`, and whose dependencies are `Done`. If the user named an item, take that one.
2. **Check it is still missing.** Search the code for the feature before building; several sessions work this backlog. If it already exists, verify it and go to step 7.
3. **Plan against the acceptance criteria.** Write each criterion as a test you will add. If a criterion needs an owner decision (a purchase, a legal or pricing choice, a third-party account), stop and report it.
4. **Build** with the `cloudsneeker-feature` skill.
5. **Review.** Start a sub-agent with only the diff and the acceptance criteria, and ask for correctness bugs, tenant-isolation gaps, and missed criteria. Fix what it confirms.
6. **Ship and verify** with the `cloudsneeker-ship` skill.
7. **Update the row.** Set Status, and append what shipped to the acceptance criteria cell: the route, the page, the migration number, and what was not exercised live. Then run:

   ```bash
   python skills/cloudsneeker-backlog/assets/validate_backlog.py
   ```

8. **Add what you found.** New gaps become new rows at the end of their priority band with the next free ID. Do not renumber existing rows.

## Row Format

Ten cells: ID, Title, Domain, Priority, Effort, Area, Dependencies, Status, Owner, Acceptance criteria.

| Cell | Allowed values |
| --- | --- |
| ID | `EB-` and three digits, unique |
| Priority | `P0`, `P1`, `P2` |
| Effort | `S`, `M`, `L` |
| Status | `Todo`, `In progress`, `Done (pending deploy)`, `Done` |
| Owner | `Buildable`, `Blocked: needs owner` |
