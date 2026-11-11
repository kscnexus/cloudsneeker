"""Global search across Cloud Security, Application Security and Governance.

``GET /api/v1/search?filter[search]=<text>`` (at least two characters) returns
one entry per group (``services/global_search.py``) with ``count`` and the
first hits. Reads follow provider visibility and the plan's product areas.
"""

from __future__ import annotations

from api.base_views import BaseRLSViewSet
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX, FindingTriage
from cloudsneeker_api.serializers_triage import FindingTriageSerializer
from cloudsneeker_api.services import entitlements
from cloudsneeker_api.services.global_search import (
    GlobalSearchError,
    clean_query,
    search,
)
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

SEARCH_GROUP_RESOURCE = f"{JSON_API_TYPE_PREFIX}search-groups"


class GlobalSearchViewSet(BaseRLSViewSet):
    """One query across every product area."""

    queryset = FindingTriage.objects.none()
    serializer_class = FindingTriageSerializer
    http_method_names = ["get", "head", "options"]
    pagination_class = None
    filter_backends = []

    def set_required_permissions(self):
        self.required_permissions = []

    @extend_schema(
        tags=["Search"],
        summary="Search findings, accounts, targets, applications, policies and alert rules",
        responses={200: OpenApiResponse(description="Search groups")},
    )
    def list(self, request, *args, **kwargs):
        # Hand-built envelope; disable JSON:API re-wrapping.
        self.resource_name = False
        try:
            text = clean_query(
                request.query_params.get("filter[search]")
                or request.query_params.get("q")
            )
        except GlobalSearchError as exc:
            raise ValidationError({"detail": str(exc)}) from exc
        tenant_id = str(request.tenant_id)
        try:
            plan = entitlements.for_tenant(tenant_id)
        except Exception:  # noqa: BLE001 - fail open like the plan middleware
            plan = entitlements.fallback_entitlements(tenant_id)
        groups = search(tenant_id, self.user_role, plan, text)
        return Response(
            {
                "data": [
                    {
                        "type": SEARCH_GROUP_RESOURCE,
                        "id": group.kind,
                        "attributes": {
                            "count": group.count,
                            "hits": [
                                {
                                    "id": hit.id,
                                    "title": hit.title,
                                    "subtitle": hit.subtitle,
                                    **hit.attributes,
                                }
                                for hit in group.hits
                            ],
                        },
                    }
                    for group in groups
                ],
                "meta": {"query": text},
            }
        )
