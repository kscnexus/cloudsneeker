"""Limit a report to one Application Security target.

A report run created with ``params.target_id`` reads only the scans that
target produced, is pinned to the target's provider (so provider visibility
rules keep applying), and is named after the target.
"""

from __future__ import annotations

from typing import Any

from cloudsneeker_api.models import TrivyTarget
from cloudsneeker_api.reports.catalog import (
    SAST,
    SCA,
    TARGET_NAME_PARAM,
    TARGET_PARAM,
    ReportParamsError,
)

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
        .only("id", "name", "mode", "provider_id")
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
        TARGET_NAME_PARAM: target.name,
    }
