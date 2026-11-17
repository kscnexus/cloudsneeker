"""Extra branches of a repository target.

A repository (or static analysis) target scans its main branch
(``config.branch``, or the repository default) and, optionally, extra
branches named by ``config.branches``: branch names or glob patterns such as
``release/*``. One target therefore covers many branches; there is no need
for one target per branch.

Each scan of the target queues one run for the main branch and then, in a
Celery task, one run per matching extra branch (``TrivyRun.branch``). A
branch whose head commit is the one its latest completed run scanned is
skipped, and at most ``APPSEC_MAX_BRANCHES_PER_SCAN`` branches are queued
per scan, in the order of the remote listing (by name).

Extra-branch findings are kept on the target with their branch
(``AppSecFinding.branch``). Only the main branch writes the shared
``Scan`` / ``Finding`` rows and the inventory, so reports, alerts and the
outbound integrations keep following the main branch.
"""

from __future__ import annotations

import fnmatch
import logging
import os
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

MAX_PATTERNS = 50
MAX_PATTERN_LENGTH = 200
# Branch characters plus the glob wildcards ``*``, ``?`` and ``[...]``.
_PATTERN_RE = re.compile(r"^[\w*?\[\]][\w./@+*?\[\]-]{0,199}$")


class BranchPolicyError(ValueError):
    """``config.branches`` is invalid."""


def max_branches_per_scan() -> int:
    try:
        value = int(os.environ.get("APPSEC_MAX_BRANCHES_PER_SCAN", "20"))
    except ValueError:
        value = 20
    return max(0, min(value, 200))


def is_pattern(value: str) -> bool:
    return any(char in value for char in "*?[")


def normalize_branch_patterns(value: Any) -> list[str]:
    """Validate ``config.branches``.

    Args:
        value: List of branch names or glob patterns; a comma or newline
            separated string is accepted too.

    Returns:
        De-duplicated names and patterns, in the order given.

    Raises:
        BranchPolicyError: Not a list, too many entries, or an unsafe value.
    """
    from cloudsneeker_api.services.repo_branches import normalize_branch

    if value in (None, "", []):
        return []
    if isinstance(value, str):
        value = re.split(r"[,\n]", value)
    if not isinstance(value, list):
        raise BranchPolicyError("config.branches must be a list of branch names.")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise BranchPolicyError("config.branches must be a list of branch names.")
        name = item.strip()
        if not name:
            continue
        if is_pattern(name):
            if (
                len(name) > MAX_PATTERN_LENGTH
                or not _PATTERN_RE.match(name)
                or ".." in name
                or "//" in name
            ):
                raise BranchPolicyError(f"'{name}' is not a valid branch pattern.")
        else:
            try:
                name = normalize_branch(name)
            except ValueError:
                raise BranchPolicyError(
                    f"'{name}' is not a valid Git branch name."
                ) from None
        if name and name not in result:
            result.append(name)
    if len(result) > MAX_PATTERNS:
        raise BranchPolicyError(
            f"config.branches allows at most {MAX_PATTERNS} names or patterns."
        )
    return result


def matching_branches(
    patterns: list[str], branches: list[str], *, exclude: set[str] = frozenset()
) -> list[str]:
    """Branches that match a name or pattern, in listing order.

    Args:
        patterns: ``config.branches``.
        branches: Remote branch names.
        exclude: Names never returned (the main branch).
    """
    if not patterns:
        return []
    return [
        branch
        for branch in branches
        if branch not in exclude
        and any(
            fnmatch.fnmatchcase(branch, pattern)
            if is_pattern(pattern)
            else branch == pattern
            for pattern in patterns
        )
    ]


@dataclass(frozen=True)
class BranchRun:
    branch: str
    commit: str


def plan_branch_runs(
    candidates: list[str],
    commits: dict[str, str],
    last_scanned: dict[str, str],
    *,
    limit: int,
    force: bool = False,
) -> tuple[list[BranchRun], list[str]]:
    """Which extra branches to queue.

    Args:
        candidates: Matching branches, in priority order.
        commits: Head commit per branch from the remote listing.
        last_scanned: Commit the latest completed run of each branch scanned.
        limit: Most branches to queue.
        force: Queue unchanged branches too (a manual "scan all branches").

    Returns:
        ``(runs, skipped)``; ``skipped`` lists unchanged branches.
    """
    runs: list[BranchRun] = []
    skipped: list[str] = []
    for branch in candidates:
        commit = commits.get(branch, "")
        if not force and commit and last_scanned.get(branch) == commit:
            skipped.append(branch)
            continue
        if len(runs) >= limit:
            break
        runs.append(BranchRun(branch=branch, commit=commit))
    return runs, skipped


def target_patterns(target) -> list[str]:
    config = target.config if isinstance(target.config, dict) else {}
    patterns = config.get("branches")
    return list(patterns) if isinstance(patterns, list) else []


def _last_scanned_commits(tenant_id: str, target_id: str) -> dict[str, str]:
    from cloudsneeker_api.models import TrivyRun

    result: dict[str, str] = {}
    rows = (
        TrivyRun.objects.filter(
            tenant_id=tenant_id, target_id=target_id, status=TrivyRun.Status.COMPLETED
        )
        .exclude(branch="")
        .order_by("branch", "-finished_at")
        .values_list("branch", "summary")
    )
    for branch, summary in rows:
        if branch not in result:
            result[branch] = str((summary or {}).get("commit") or "")
    return result


def queue_branch_runs(
    *,
    tenant_id: str,
    target_id: str,
    trigger: str,
    triggered_by_id: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """List the repository's branches and queue a run per matching branch.

    Runs inside the Celery task ``cloudsneeker-appsec-branch-runs``: listing
    branches is a network call.

    Returns:
        ``{"queued": [...], "skipped": [...], "matched": n, "error": str}``.
    """
    from api.db_utils import rls_transaction
    from cloudsneeker_api.models import TrivyRun, TrivyTarget
    from cloudsneeker_api.services.repo_branches import (
        RepositoryBranchError,
        list_repository_branches,
    )
    from cloudsneeker_api.tasks import trivy_scan_task
    from django.db import transaction

    with rls_transaction(tenant_id):
        target = (
            TrivyTarget.objects.select_related("provider", "provider__secret")
            .filter(tenant_id=tenant_id, id=target_id)
            .first()
        )
    if target is None:
        return {"queued": [], "skipped": [], "matched": 0, "error": "Target not found."}
    patterns = target_patterns(target)
    url = str((target.config or {}).get("repository_url") or "")
    if not patterns or not url:
        return {"queued": [], "skipped": [], "matched": 0, "error": ""}
    try:
        listing = list_repository_branches(url, target.provider)
    except RepositoryBranchError as exc:
        logger.warning("Branch listing failed for target %s: %s", target_id, exc)
        return {"queued": [], "skipped": [], "matched": 0, "error": str(exc)}

    main = str((target.config or {}).get("branch") or listing.default_branch)
    candidates = matching_branches(patterns, listing.branches, exclude={main})
    with rls_transaction(tenant_id):
        last = _last_scanned_commits(tenant_id, target_id)
        active = set(
            TrivyRun.objects.filter(
                tenant_id=tenant_id,
                target_id=target_id,
                status__in=[TrivyRun.Status.PENDING, TrivyRun.Status.RUNNING],
            )
            .exclude(branch="")
            .values_list("branch", flat=True)
        )
        runs, skipped = plan_branch_runs(
            [branch for branch in candidates if branch not in active],
            listing.commits,
            last,
            limit=max_branches_per_scan(),
            force=force,
        )
        created = [
            TrivyRun.objects.create(
                tenant_id=tenant_id,
                target=target,
                provider=target.provider,
                status=TrivyRun.Status.PENDING,
                trigger=trigger,
                triggered_by_id=triggered_by_id,
                branch=item.branch,
                summary={"commit": item.commit} if item.commit else {},
            )
            for item in runs
        ]
        run_ids = [str(run.id) for run in created]

        def dispatch() -> None:
            for run_id in run_ids:
                trivy_scan_task.delay(tenant_id=tenant_id, run_id=run_id)

        transaction.on_commit(dispatch)
    return {
        "queued": [item.branch for item in runs],
        "skipped": skipped,
        "matched": len(candidates),
        "error": "",
    }
