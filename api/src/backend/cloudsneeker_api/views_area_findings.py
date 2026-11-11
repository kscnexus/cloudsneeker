"""Area findings API: one findings list for each product area.

``GET /api/v1/area-findings?filter[area]=cloud|application_security|governance``

Filters: ``filter[severity__in]``, ``filter[triage_status__in]``,
``filter[source__in]`` (provider, target or policy ids), ``filter[search]``,
``filter[category__in]`` (Application Security: sast, sca, secrets, iac,
container; adds ``meta.category_counts`` and ``meta.enabled_categories``),
``filter[priority__in]`` (p0-p4), ``filter[overdue]=true``,
``filter[application__in]`` (linked provider ids) and ``filter[uid]``
(Application Security; adds ``meta.priority_counts`` and
``meta.overdue_count``). ``summary=applications`` adds ``meta.applications``
with totals per linked provider,
``filter[muted]=include``, ``filter[status]=all`` (passed findings too).
Sort: ``severity`` (default), ``last_seen_at``, ``first_seen_at``,
``check_id``; ``-`` reverses. Paginated with ``page[number]`` and
``page[size]`` (at most 100). ``meta.sources`` lists the area's sources for a
filter control.

Reading follows provider visibility. Each area also needs its plan feature.
Triage changes use the ``finding-triages`` routes.

``POST /api/v1/area-findings/mute`` (``manage_scans``) creates one shared
mute rule from finding UIDs of any area: ``finding_uids``, ``name``,
``reason``. Governance findings have no ``Finding`` row, so the upstream
``mute-rules`` endpoint (which takes ``Finding`` ids) cannot mute them.
"""

from __future__ import annotations

import math

from api.base_views import BaseRLSViewSet
from api.rbac.permissions import Permissions
from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX, FindingTriage
from cloudsneeker_api.serializers_triage import FindingTriageSerializer
from cloudsneeker_api.services import entitlements
from cloudsneeker_api.services.area_findings import (
    AREA_FEATURE,
    AreaFindingsError,
    list_area_findings,
    parse_query,
)
from cloudsneeker_api.services.area_mute import AreaMuteError, create_area_mute_rule
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.parsers import JSONParser
from rest_framework.response import Response

AREA_FINDING_RESOURCE = f"{JSON_API_TYPE_PREFIX}area-findings"


def _iso(value):
    return value.isoformat() if value else None


class AreaFindingViewSet(BaseRLSViewSet):
    """Current findings of one product area, with triage."""

    queryset = FindingTriage.objects.none()
    serializer_class = FindingTriageSerializer
    http_method_names = ["get", "post", "head", "options"]
    pagination_class = None
    filter_backends = []
    parser_classes = [LenientJSONAPIParser, JSONParser]

    def set_required_permissions(self):
        if self.action == "mute":
            self.required_permissions = [Permissions.MANAGE_SCANS]
        else:
            self.required_permissions = []

    @extend_schema(
        tags=["Finding triage"],
        summary="Mute findings of any product area",
        request=None,
        responses={201: OpenApiResponse(description="Mute rule created")},
    )
    @action(detail=False, methods=["post"], url_path="mute")
    def mute(self, request, *args, **kwargs):
        self.resource_name = False
        payload = request.data or {}
        if isinstance(payload.get("attributes"), dict):
            payload = payload["attributes"]
        uids = payload.get("finding_uids") or []
        if not isinstance(uids, list):
            raise ValidationError({"finding_uids": "Send a list of finding UIDs."})
        try:
            result = create_area_mute_rule(
                tenant_id=str(request.tenant_id),
                role=self.user_role,
                user=request.user,
                finding_uids=[str(uid) for uid in uids],
                name=str(payload.get("name") or ""),
                reason=str(payload.get("reason") or ""),
            )
        except AreaMuteError as exc:
            raise ValidationError({"detail": str(exc)}) from exc
        rule = result.rule
        return Response(
            {
                "data": {
                    "type": "mute-rules",
                    "id": str(rule.id),
                    "attributes": {
                        "name": rule.name,
                        "reason": rule.reason,
                        "enabled": rule.enabled,
                        "finding_uids": rule.finding_uids,
                        "inserted_at": _iso(rule.inserted_at),
                    },
                },
                "meta": {"skipped_uids": result.skipped_uids},
            },
            status=status.HTTP_201_CREATED,
        )

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
                            **(
                                {"due_at": _iso(row["due_at"])}
                                if "due_at" in row
                                else {}
                            ),
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
                    **(
                        {
                            "category_counts": page.category_counts,
                            "enabled_categories": page.enabled_categories,
                            "priority_counts": page.priority_counts,
                            "overdue_count": page.overdue_count,
                            **(
                                {"applications": page.applications}
                                if page.applications is not None
                                else {}
                            ),
                        }
                        if page.category_counts is not None
                        else {}
                    ),
                },
            }
        )
