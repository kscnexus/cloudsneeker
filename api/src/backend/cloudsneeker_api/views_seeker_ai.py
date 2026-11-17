"""Assistant request metering (EB-080).

The chat runs in the web app, so the API never sees a chat message. The web
app calls ``POST /api/v1/seeker-ai/requests`` once before each chat request:

* ``SubscriptionEnforcementMiddleware`` answers 403 ``plan_limit_reached``
  when the month's ``seeker_ai_requests_per_month`` allowance is used, or
  ``feature_not_in_plan`` when the plan has no assistant;
* otherwise this view answers 201 and ``AuditLogMiddleware`` writes the
  ``seeker_ai.request`` audit event that the monthly count reads
  (``services/entitlements.py``). No other table records assistant requests.
"""

from __future__ import annotations

from api.base_views import BaseRLSViewSet
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX, AuditEvent
from cloudsneeker_api.serializers_audit import AuditEventSerializer
from cloudsneeker_api.services import entitlements
from cloudsneeker_api.services import plan_catalog as catalog
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.response import Response

SEEKER_AI_REQUEST_RESOURCE = f"{JSON_API_TYPE_PREFIX}seeker-ai-requests"


class SeekerAiRequestViewSet(BaseRLSViewSet):
    """Record one assistant request against the monthly allowance."""

    queryset = AuditEvent.objects.none()
    serializer_class = AuditEventSerializer
    http_method_names = ["post", "options"]
    pagination_class = None
    filter_backends = []

    def set_required_permissions(self):
        self.required_permissions = []

    @extend_schema(
        tags=["Assistant"],
        summary="Record an assistant request against the plan's monthly allowance",
        request=None,
        responses={
            201: OpenApiResponse(description="Request recorded"),
            403: OpenApiResponse(description="Monthly allowance used"),
        },
    )
    def create(self, request, *_args, **_kwargs):
        # Hand-built envelope; disable JSON:API re-wrapping.
        self.resource_name = False
        tenant_id = str(request.tenant_id)
        try:
            limit = entitlements.for_tenant(tenant_id).limit(
                catalog.LIMIT_SEEKER_AI_REQUESTS_PER_MONTH
            )
        except Exception:  # noqa: BLE001 - fail open like the plan middleware
            limit = None
        return Response(
            {
                "data": {
                    "type": SEEKER_AI_REQUEST_RESOURCE,
                    "id": tenant_id,
                    "attributes": {"limit": limit},
                }
            },
            status=status.HTTP_201_CREATED,
        )
