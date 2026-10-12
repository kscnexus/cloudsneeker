from api.authentication import CombinedJWTOrAPIKeyAuthentication
from cloudsneeker_api.brand import brand
from cloudsneeker_api.serializers import BrandSerializer
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, status
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

BRAND_RESOURCE_TYPE = BrandSerializer.Meta.resource_name


class JSONAPIDocumentRenderer(JSONRenderer):
    """Plain JSON renderer that labels a hand-built JSON:API document."""

    media_type = "application/vnd.api+json"
    format = "vnd.api+json"


def brand_document() -> dict:
    """Build the JSON:API document describing the product brand.

    Returns:
        A single-resource JSON:API document of type ``cloudsneeker-brand``.
    """
    return {
        "data": {
            "type": BRAND_RESOURCE_TYPE,
            "id": brand.slug,
            "attributes": BrandSerializer(brand).data,
        }
    }


@extend_schema(
    tags=["Cloudsneeker"],
    summary="Retrieve the product brand",
    responses={200: BrandSerializer},
)
class BrandView(APIView):
    """Expose the brand values the web app and other clients should display.

    Requires a signed-in session or an API key like every other ``/api/v1``
    endpoint.
    """

    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    renderer_classes = [JSONAPIDocumentRenderer]
    serializer_class = BrandSerializer

    def get(self, _request, *_args, **_kwargs):
        return Response(brand_document(), status=status.HTTP_200_OK)
