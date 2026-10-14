"""JSON:API views for per-tenant Slack app credentials."""

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from api.base_views import BaseRLSViewSet
from api.rbac.permissions import Permissions
from cloudsneeker_api.models import SlackAppConfig
from cloudsneeker_api.serializers_slack_app import (
    SlackAppConfigSerializer,
    SlackAppConfigWriteSerializer,
)
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response


@extend_schema_view(
    list=extend_schema(
        tags=["Slack App"],
        summary="Get the tenant Slack app configuration",
    ),
    create=extend_schema(
        tags=["Slack App"],
        summary="Create the tenant Slack app configuration",
    ),
    retrieve=extend_schema(
        tags=["Slack App"],
        summary="Retrieve the tenant Slack app configuration",
    ),
    partial_update=extend_schema(
        tags=["Slack App"],
        summary="Update the tenant Slack app configuration",
    ),
    destroy=extend_schema(
        tags=["Slack App"],
        summary="Delete the tenant Slack app configuration",
    ),
)
class SlackAppConfigViewSet(BaseRLSViewSet):
    queryset = SlackAppConfig.objects.all()
    serializer_class = SlackAppConfigSerializer
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    required_permissions = [Permissions.MANAGE_INTEGRATIONS]

    def get_queryset(self):
        return SlackAppConfig.objects.filter(tenant_id=self.request.tenant_id)

    def get_serializer_class(self):
        if self.action in ("create", "partial_update"):
            return SlackAppConfigWriteSerializer
        return SlackAppConfigSerializer

    def create(self, request, *args, **kwargs):
        if self.get_queryset().exists():
            raise ValidationError(
                {
                    "detail": "Slack app configuration already exists. Use PATCH to update it."
                }
            )
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        config = serializer.save()
        return Response(
            SlackAppConfigSerializer(
                config, context=self.get_serializer_context()
            ).data,
            status=status.HTTP_201_CREATED,
        )

    def partial_update(self, request, *args, **kwargs):
        config = self.get_object()
        serializer = self.get_serializer(config, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        config = serializer.save()
        return Response(
            SlackAppConfigSerializer(
                config, context=self.get_serializer_context()
            ).data
        )


SlackAppConfigViewSet.authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
