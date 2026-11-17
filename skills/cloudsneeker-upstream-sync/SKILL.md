---
name: cloudsneeker-upstream-sync
description: >
  Merges an upstream Prowler release into Cloudsneeker and restores the recorded hooks.
  Trigger: When merging or rebasing on upstream Prowler, resolving a merge conflict in an inherited file, or fixing a stale rebrand rule after a merge.
license: Apache-2.0
metadata:
  author: cloudsneeker
  version: "1.0"
  scope: [root]
  auto_invoke:
    - "Merging an upstream Prowler release into Cloudsneeker"
    - "Resolving a merge conflict in an inherited Prowler file"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

## Critical Rules

- NEVER push to the `upstream` remote.
- On a conflict, ALWAYS take the upstream side of the file, then re-apply the hook rows for that file from `knowledge-base/upstream-hooks.md`. Do not replay the old Cloudsneeker edit on top.
- NEVER resolve a conflict by dropping an upstream change or an upstream test.
- Ask before starting: a merge touches thousands of files and blocks other branches until it lands.

## Steps

1. Start from a clean branch off `github/main`. `git fetch upstream --tags`.
2. Run `pwsh cloudsneeker/tools/sync-upstream.ps1 -Tag <tag>` (newest tag by default; where PowerShell 7 is not installed, `powershell -File` runs the same script). It merges with `--no-ff` and stops on conflicts.
3. For each conflicted file: take upstream, find its rows in `upstream-hooks.md`, re-apply each hook, and keep the `cloudsneeker-hook` marker on the line.
4. Commit, then run the script again. It runs the rebrand check, the brand audit, the release-notes generator, and the Cloudsneeker suites. Commit the regenerated `cloudsneeker/content/releases.json`.
5. Fix each stale rebrand rule the check reports: update the rule and its fixture in `tests/cloudsneeker/tools/rebrand_test.py`, or retire it.
6. Keep the newer version of every pin listed under "Security version bumps" in `upstream-hooks.md`.
7. Regenerate the docs: `python cloudsneeker/tools/gen_check_docs.py`, then `python cloudsneeker/tools/brand_audit.py --tree cloudsneeker/docs`.
8. Look for new client-visible upstream surfaces ("New Upstream Surfaces" in `knowledge-base/upstream-sync.md`). Each audit hit becomes a rule, a hook, or an allowlist entry.
9. Ship with the `cloudsneeker-ship` skill. Skip its placement check on a merge branch: every file upstream changed shows as modified there. The live check for a merge is the smoke list in step 8 of `knowledge-base/upstream-sync.md`.

## Reference

`knowledge-base/upstream-sync.md` holds the full procedure and the list of what must stay untouched.
