"""JSON:API views for per-tenant SMTP email delivery."""

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from api.base_views import BaseRLSViewSet
from api.models import User
from api.rbac.permissions import Permissions
from cloudsneeker_api.models import EmailDeliveryConfig
from cloudsneeker_api.serializers_email import (
    EmailDeliveryConfigSerializer,
    EmailDeliveryConfigWriteSerializer,
)
from cloudsneeker_api.services.email_delivery import send_with_tenant_smtp
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response


@extend_schema_view(
    list=extend_schema(
        tags=["Email Delivery"],
        summary="Get the tenant SMTP configuration",
    ),
    create=extend_schema(
        tags=["Email Delivery"],
        summary="Create the tenant SMTP configuration",
    ),
    retrieve=extend_schema(
        tags=["Email Delivery"],
        summary="Retrieve the tenant SMTP configuration",
    ),
    partial_update=extend_schema(
        tags=["Email Delivery"],
        summary="Update the tenant SMTP configuration",
    ),
    destroy=extend_schema(
        tags=["Email Delivery"],
        summary="Delete the tenant SMTP configuration",
    ),
)
class EmailDeliveryConfigViewSet(BaseRLSViewSet):
    queryset = EmailDeliveryConfig.objects.all()
    serializer_class = EmailDeliveryConfigSerializer
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    required_permissions = [Permissions.MANAGE_INTEGRATIONS]

    def get_queryset(self):
        return EmailDeliveryConfig.objects.filter(tenant_id=self.request.tenant_id)

    def get_serializer_class(self):
        if self.action in ("create", "partial_update"):
            return EmailDeliveryConfigWriteSerializer
        return EmailDeliveryConfigSerializer

    def create(self, request, *args, **kwargs):
        if self.get_queryset().exists():
            raise ValidationError(
                {"detail": "SMTP configuration already exists. Use PATCH to update it."}
            )
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        config = serializer.save()
        return Response(
            EmailDeliveryConfigSerializer(
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
            EmailDeliveryConfigSerializer(
                config, context=self.get_serializer_context()
            ).data
        )

    @extend_schema(
        tags=["Email Delivery"],
        summary="Send a test email to the current user",
        request=None,
        responses={200: None},
    )
    @action(detail=True, methods=["post"], url_path="test")
    def test(self, request, pk=None):
        config = self.get_object()
        if not config.enabled:
            raise ValidationError({"detail": "SMTP configuration is disabled."})

        user = User.objects.filter(id=request.user.id).first()
        recipient = getattr(user, "email", None) if user else None
        if not recipient:
            raise ValidationError(
                {"detail": "Your user account has no email address for the test."}
            )

        try:
            send_with_tenant_smtp(
                tenant_id=str(request.tenant_id),
                subject="[Cloudsneeker] SMTP test",
                message=(
                    "This is a test message from Cloudsneeker confirming your "
                    "SMTP settings."
                ),
                recipient_list=[recipient],
                config=config,
            )
        except Exception as exc:
            raise ValidationError({"detail": f"SMTP test failed: {exc}"}) from exc

        return Response(
            {
                "data": {
                    "type": "email-delivery-tests",
                    "id": str(config.id),
                    "attributes": {"sent_to": recipient},
                }
            }
        )


# Keep authentication explicit for OpenAPI discovery of the test action.
EmailDeliveryConfigViewSet.authentication_classes = [
    CombinedJWTOrAPIKeyAuthentication
]
