"""Which sources (providers) a report may cover.

``catalog.SOURCE_PROVIDER_TYPES`` says which provider types each report
reads. New requests (API, Generate dialog, schedule form, assessment wizard)
that name a provider of another type are rejected with a 400. Stored
schedules and role-pinned provider lists are not rejected: at run time the
inapplicable providers are dropped with a warning in the log. When every
listed provider would be dropped the list is kept unchanged, because an empty
``provider_ids`` means "every provider" and would widen a role-pinned scope;
the report is then empty, which is what that scope holds for the report.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from api.db_utils import rls_transaction
from api.models import Provider
from cloudsneeker_api.reports.catalog import (
    ReportParamsError,
    applicable_provider_types,
    inapplicable_provider_ids,
    source_scope_message,
)

logger = logging.getLogger(__name__)


def provider_types_of(tenant_id: str, provider_ids: Iterable[str]) -> dict[str, str]:
    """Return provider id to provider type for the tenant's providers.

    Unknown ids are left out; they are not this module's concern.
    """
    ids = sorted({str(item) for item in provider_ids})
    if not ids:
        return {}
    with rls_transaction(str(tenant_id)):
        rows = Provider.all_objects.filter(tenant_id=tenant_id, id__in=ids).values_list(
            "id", "provider"
        )
        return {str(provider_id): str(provider_type) for provider_id, provider_type in rows}


def _rejected(tenant_id: str, report_type: str, params: dict[str, Any]) -> dict[str, str]:
    provider_ids = list((params or {}).get("provider_ids") or [])
    if (
        not tenant_id
        or not provider_ids
        or applicable_provider_types(report_type) is None
    ):
        return {}
    types = provider_types_of(tenant_id, provider_ids)
    return {
        provider_id: types[provider_id]
        for provider_id in inapplicable_provider_ids(report_type, types)
    }


def check_source_scope(tenant_id: str, report_type: str, params: dict[str, Any]) -> None:
    """Reject providers the report does not read.

    Raises:
        ReportParamsError: A listed provider's type does not apply.
    """
    rejected = _rejected(tenant_id, report_type, params)
    if rejected:
        raise ReportParamsError(source_scope_message(report_type, rejected))


def drop_inapplicable_sources(
    tenant_id: str, report_type: str, params: dict[str, Any]
) -> dict[str, Any]:
    """Return ``params`` without providers the report does not read.

    Used at run time for stored schedules and role-pinned lists. The list is
    kept as is when nothing applicable would remain (see the module note).
    """
    rejected = _rejected(tenant_id, report_type, params)
    if not rejected:
        return params
    kept = [item for item in params["provider_ids"] if item not in rejected]
    if not kept:
        logger.warning(
            "Report %s: no listed source applies (%s); keeping the list.",
            report_type,
            ", ".join(sorted(set(rejected.values()))),
        )
        return params
    logger.warning(
        "Report %s: dropped %d source(s) of type %s that the report does not read.",
        report_type,
        len(rejected),
        ", ".join(sorted(set(rejected.values()))),
    )
    return {**params, "provider_ids": kept}
