"""Content versions panel (EB-048).

``GET /content-versions``: posture content release, vulnerability database
age, code analysis rules and engine versions. Read-only and the same for
every organization; any signed-in user or API key can read it.
"""

from __future__ import annotations

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX
from cloudsneeker_api.services.content_versions import content_versions
from cloudsneeker_api.views import JSONAPIDocumentRenderer
from drf_spectacular.utils import extend_schema
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

TYPE_CONTENT_VERSIONS = f"{JSON_API_TYPE_PREFIX}content-versions"
RESOURCE_ID = "current"


@extend_schema(exclude=True)
class ContentVersionsView(APIView):
    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    renderer_classes = [JSONAPIDocumentRenderer]

    def get(self, request):
        return Response(
            {
                "data": {
                    "type": TYPE_CONTENT_VERSIONS,
                    "id": RESOURCE_ID,
                    "attributes": content_versions(),
                }
            }
        )
