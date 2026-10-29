"""Provider visibility rules for reports.

Reports follow the same visibility as findings: a role with
``unlimited_visibility`` sees every provider of the tenant; any other role
only sees the providers of its provider groups. Report parameters store the
resolved provider list, so a report generated later by a worker (or a
schedule) never reads beyond what its creator could see.
"""

from __future__ import annotations

from typing import Any

from api.models import Provider, Role
from api.rbac.permissions import get_providers
from django.db.models import Q, QuerySet


class ReportAccessError(PermissionError):
    """Raised when a user asks for providers outside their visibility."""


def visible_provider_ids(role: Role) -> set[str] | None:
    """Return the provider ids a role can see, or ``None`` for every provider."""
    if role.unlimited_visibility:
        return None
    return {str(pk) for pk in get_providers(role).values_list("id", flat=True)}


def scope_params_to_role(params: dict[str, Any], role: Role) -> dict[str, Any]:
    """Pin ``provider_ids`` to the role's visibility.

    Args:
        params: Normalized report parameters.
        role: Requesting user's role.

    Returns:
        Parameters with ``provider_ids`` set to the requested providers (all
        visible) or, when none were requested by a limited role, to every
        visible provider.

    Raises:
        ReportAccessError: A requested provider is not visible, or a limited
            role sees no provider at all (an empty list would mean "all").
    """
    visible = visible_provider_ids(role)
    if visible is None:
        return params
    requested = set(params.get("provider_ids") or [])
    if requested:
        if not requested <= visible:
            raise ReportAccessError("One or more providers are not visible to you.")
        return params
    if not visible:
        raise ReportAccessError("Your role cannot see any provider.")
    return {**params, "provider_ids": sorted(visible)}


def params_visible_to_role(params: dict[str, Any], role: Role) -> bool:
    """True when every provider a report covers is visible to ``role``.

    Reports with no provider list cover the whole tenant and are only visible
    to unlimited roles.
    """
    visible = visible_provider_ids(role)
    if visible is None:
        return True
    provider_ids = set((params or {}).get("provider_ids") or [])
    return bool(provider_ids) and provider_ids <= visible


def filter_runs_for_role(queryset: QuerySet, role: Role, user_id: Any) -> QuerySet:
    """Limit a run / schedule queryset to what a role may read.

    Unlimited roles see every row; limited roles see the rows they created
    plus rows whose stored providers are all visible to them.

    Args:
        queryset: ``ReportRun`` or ``ReportSchedule`` queryset.
        role: Requesting user's role.
        user_id: Requesting user id.

    Returns:
        Filtered queryset.
    """
    visible = visible_provider_ids(role)
    if visible is None:
        return queryset
    hidden = Provider.all_objects.filter(tenant_id=role.tenant_id).exclude(
        id__in=list(visible)
    )
    condition = Q(created_by_id=user_id)
    # Rows that store a non-empty provider list none of whose ids are hidden.
    visible_rows = ~Q(params__provider_ids=[])
    for provider_id in hidden.values_list("id", flat=True):
        visible_rows &= ~Q(params__provider_ids__contains=[str(provider_id)])
    if visible:
        condition |= visible_rows & Q(params__has_key="provider_ids")
    return queryset.filter(condition)
