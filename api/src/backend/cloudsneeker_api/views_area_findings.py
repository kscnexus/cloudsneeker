"""Area findings API: one findings list for each product area.

``GET /api/v1/area-findings?filter[area]=cloud|application_security|governance``

Filters: ``filter[severity__in]``, ``filter[triage_status__in]``,
``filter[source__in]`` (provider, target or policy ids), ``filter[search]``,
``filter[muted]=include``, ``filter[status]=all`` (passed findings too).
Sort: ``severity`` (default), ``last_seen_at``, ``first_seen_at``,
``check_id``; ``-`` reverses. Paginated with ``page[number]`` and
``page[size]`` (at most 100). ``meta.sources`` lists the area's sources for a
filter control.

Reading follows provider visibility. Each area also needs its plan feature.
Triage changes use the ``finding-triages`` routes.
"""

from __future__ import annotations

import math

from api.base_views import BaseRLSViewSet
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX, FindingTriage
from cloudsneeker_api.serializers_triage import FindingTriageSerializer
from cloudsneeker_api.services import entitlements
from cloudsneeker_api.services.area_findings import (
    AREA_FEATURE,
    AreaFindingsError,
    list_area_findings,
    parse_query,
)
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response

AREA_FINDING_RESOURCE = f"{JSON_API_TYPE_PREFIX}area-findings"


def _iso(value):
    return value.isoformat() if value else None


class AreaFindingViewSet(BaseRLSViewSet):
    """Current findings of one product area, with triage."""

    queryset = FindingTriage.objects.none()
    serializer_class = FindingTriageSerializer
    http_method_names = ["get", "head", "options"]
    pagination_class = None
    filter_backends = []

    def set_required_permissions(self):
        self.required_permissions = []

    @extend_schema(
        tags=["Finding triage"],
        summary="List the current findings of a product area",
        responses={200: OpenApiResponse(description="Area findings with triage")},
    )
    def list(self, request, *args, **kwargs):
        # Hand-built envelope; disable JSON:API re-wrapping (no ``data.data``).
        self.resource_name = False
        try:
            query = parse_query(request.query_params)
        except AreaFindingsError as exc:
            raise ValidationError({"detail": str(exc)}) from exc
        tenant_id = str(request.tenant_id)
        try:
            plan = entitlements.for_tenant(tenant_id)
        except Exception:  # noqa: BLE001 - fail open like the plan middleware
            plan = entitlements.fallback_entitlements(tenant_id)
        if not plan.has_feature(AREA_FEATURE[query.area]):
            raise PermissionDenied("This area is not included in your plan.")
        page = list_area_findings(tenant_id, self.user_role, query)
        return Response(
            {
                "data": [
                    {
                        "type": AREA_FINDING_RESOURCE,
                        "id": row["uid"],
                        "attributes": {
                            **row,
                            "first_seen_at": _iso(row["first_seen_at"]),
                            "last_seen_at": _iso(row["last_seen_at"]),
                        },
                    }
                    for row in page.rows
                ],
                "meta": {
                    "pagination": {
                        "page": query.page,
                        "pages": max(1, math.ceil(page.count / query.page_size)),
                        "count": page.count,
                    },
                    "sources": [
                        {"id": source.id, "name": source.name, "kind": source.kind}
                        for source in page.sources
                    ],
                },
            }
        )
