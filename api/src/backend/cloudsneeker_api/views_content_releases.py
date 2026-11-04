"""Detection content release notes (EB-049).

``GET /content-releases``: per release, the posture checks and compliance
frameworks that were added, changed or removed, newest first. Read-only and
the same for every organization; any signed-in user or API key can read it.
"""

from __future__ import annotations

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from cloudsneeker.content_releases import load_releases
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX
from cloudsneeker_api.views import JSONAPIDocumentRenderer
from drf_spectacular.utils import extend_schema
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import APIView

TYPE_CONTENT_RELEASES = f"{JSON_API_TYPE_PREFIX}content-releases"


@extend_schema(exclude=True)
class ContentReleasesView(APIView):
    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    renderer_classes = [JSONAPIDocumentRenderer]

    def get(self, request):
        return Response(
            {
                "data": [
                    {
                        "type": TYPE_CONTENT_RELEASES,
                        "id": release["version"],
                        "attributes": release,
                    }
                    for release in load_releases()
                ]
            }
        )
