"""Limit a report to one Application Security target.

A report run created with ``params.target_id`` reads only the scans that
target produced, is pinned to the target's provider (so provider visibility
rules keep applying), and is named after the target and the branch it scans
(``<target> @ <branch>``, so files read ``<target>-<branch>-sca-<date>.pdf``).
"""

from __future__ import annotations

from typing import Any

from cloudsneeker_api.models import TrivyRun, TrivyTarget
from cloudsneeker_api.reports.catalog import (
    SAST,
    SCA,
    TARGET_NAME_PARAM,
    TARGET_PARAM,
    ReportParamsError,
)
from cloudsneeker_api.services.repo_branches import branch_label, run_branch

# Target modes each target-scoped report accepts (matches the report scopes).
TARGET_MODES: dict[str, frozenset[str]] = {
    SCA: frozenset({"repo", "fs", "sbom", "image", "k8s"}),
    SAST: frozenset({"sast"}),
}


def resolve_target_scope(
    tenant_id: str, report_type: str, params: dict[str, Any]
) -> dict[str, Any]:
    """Pin normalized params to the target named by ``target_id``.

    Must run inside ``rls_transaction(tenant_id)`` (or on the admin alias);
    the query filters by ``tenant_id`` too.

    Args:
        tenant_id: Tenant UUID string.
        report_type: Catalog key.
        params: Output of ``validate_params``.

    Returns:
        ``params`` unchanged when no target is set; otherwise a copy with
        ``provider_ids`` set to the target's provider and ``target_name`` set.

    Raises:
        ReportParamsError: Unknown target, a mode the report does not cover,
            or ``provider_ids`` that exclude the target's provider.
    """
    target_id = params.get(TARGET_PARAM)
    if not target_id:
        return params
    target = (
        TrivyTarget.objects.filter(tenant_id=tenant_id, id=target_id)
        .only("id", "name", "mode", "provider_id", "config")
        .first()
    )
    if target is None:
        raise ReportParamsError("target_id does not match a target.")
    modes = TARGET_MODES.get(report_type, frozenset())
    if target.mode not in modes:
        raise ReportParamsError(
            f"This report does not cover {target.get_mode_display()} targets."
        )
    provider_id = str(target.provider_id)
    requested = set(params.get("provider_ids") or [])
    if requested and provider_id not in requested:
        raise ReportParamsError(
            "The target's source is outside the selected providers."
        )
    return {
        **params,
        "provider_ids": [provider_id],
        TARGET_NAME_PARAM: branch_label(target.name, target_branch(tenant_id, target)),
    }


def target_branch(tenant_id: str, target: TrivyTarget) -> str:
    """Branch a target scans: its ``config.branch``, else the branch its
    latest completed run recorded (the repository's default branch).

    Args:
        tenant_id: Tenant UUID string.
        target: Target with ``config`` loaded.

    Returns:
        The branch name, or "" when unknown (not a Git target, or never run).
    """
    config = target.config if isinstance(target.config, dict) else {}
    if config.get("branch"):
        return str(config["branch"])
    if not config.get("repository_url"):
        return ""
    latest = (
        TrivyRun.objects.filter(
            tenant_id=tenant_id,
            target_id=target.id,
            status=TrivyRun.Status.COMPLETED,
        )
        .order_by("-finished_at")
        .values("summary", "output", "options")
        .first()
    )
    if latest is None:
        return ""
    return run_branch(latest["summary"], latest["output"], latest["options"])
