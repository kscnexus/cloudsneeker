"""Full ``/schedules`` API matching the Cloudsneeker UI contract.

Replaces the OSS stub that only exposed ``POST /schedules/daily``.
"""

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from api.base_views import BaseRLSViewSet
from api.models import Provider, Task
from api.rbac.permissions import Permissions, get_providers
from api.v1.serializers import ScheduleDailyCreateSerializer, TaskSerializer
from cloudsneeker_api.serializers_schedules import (
    ScheduleAttributesSerializer,
    ScheduleBulkSerializer,
)
from cloudsneeker_api.services.scan_schedule import (
    ScanScheduleError,
    read_schedule_attributes,
    remove_provider_scan_schedule,
    sync_provider_scan_schedule,
)
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.urls import reverse
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import MethodNotAllowed, ValidationError
from rest_framework.response import Response
from tasks.beat import schedule_provider_scan


def _schedule_document(provider: Provider, attributes: dict) -> dict:
    return {
        "type": "schedules",
        "id": str(provider.id),
        "attributes": attributes,
        "relationships": {
            "provider": {
                "data": {"type": "providers", "id": str(provider.id)},
            }
        },
    }


@extend_schema_view(
    list=extend_schema(
        tags=["Schedule"],
        summary="List provider scan schedules",
    ),
    retrieve=extend_schema(
        tags=["Schedule"],
        summary="Retrieve a provider scan schedule",
    ),
    partial_update=extend_schema(
        tags=["Schedule"],
        summary="Create or update a provider scan schedule",
    ),
    destroy=extend_schema(
        tags=["Schedule"],
        summary="Remove a provider scan schedule",
    ),
)
class ScheduleViewSet(BaseRLSViewSet):
    """JSON:API schedules keyed by provider id."""

    queryset = Provider.objects.all()
    serializer_class = ScheduleAttributesSerializer
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    required_permissions = [Permissions.MANAGE_SCANS]
    lookup_field = "pk"

    def get_queryset(self):
        if self.user_role.unlimited_visibility:
            return Provider.objects.filter(tenant_id=self.request.tenant_id)
        return get_providers(self.user_role)

    def list(self, request, *args, **kwargs):
        providers = self.filter_queryset(self.get_queryset())
        configured_only = request.query_params.get("filter[configured]") == "true"
        data = []
        for provider in providers:
            attributes = read_schedule_attributes(provider)
            if configured_only and not attributes.get("scan_enabled"):
                continue
            data.append(_schedule_document(provider, attributes))
        return Response({"data": data})

    def retrieve(self, request, *args, **kwargs):
        provider = self.get_object()
        return Response(
            {"data": _schedule_document(provider, read_schedule_attributes(provider))}
        )

    def partial_update(self, request, *args, **kwargs):
        provider = self.get_object()
        payload = request.data or {}
        attributes = payload.get("attributes") or payload
        if isinstance(payload.get("data"), dict):
            attributes = payload["data"].get("attributes") or attributes

        serializer = ScheduleAttributesSerializer(data=attributes)
        serializer.is_valid(raise_exception=True)
        try:
            result = sync_provider_scan_schedule(
                tenant_id=str(request.tenant_id),
                provider=provider,
                **serializer.validated_data,
            )
        except ScanScheduleError as exc:
            raise ValidationError({"detail": str(exc)}) from exc
        return Response({"data": _schedule_document(provider, result)})

    def destroy(self, request, *args, **kwargs):
        provider = self.get_object()
        remove_provider_scan_schedule(
            tenant_id=str(request.tenant_id), provider=provider
        )
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(exclude=True)
    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(method="POST")

    @action(detail=False, methods=["post"], url_path="bulk")
    def bulk(self, request, *args, **kwargs):
        payload = request.data or {}
        attributes = payload.get("attributes") or payload
        if isinstance(payload.get("data"), dict):
            attributes = payload["data"].get("attributes") or attributes

        serializer = ScheduleBulkSerializer(data=attributes)
        serializer.is_valid(raise_exception=True)
        schedule = serializer.validated_data["schedule"]
        provider_ids = serializer.validated_data["provider_ids"]

        updated = []
        failed = []
        providers = {
            str(provider.id): provider
            for provider in self.get_queryset().filter(id__in=provider_ids)
        }
        for provider_id in provider_ids:
            provider = providers.get(str(provider_id))
            if not provider:
                failed.append({"id": str(provider_id), "error": "Provider not found."})
                continue
            try:
                sync_provider_scan_schedule(
                    tenant_id=str(request.tenant_id),
                    provider=provider,
                    **schedule,
                )
                updated.append(str(provider_id))
            except ScanScheduleError as exc:
                failed.append({"id": str(provider_id), "error": str(exc)})

        return Response({"data": {"updated": updated, "failed": failed}})

    @action(detail=False, methods=["post"], url_name="daily")
    def daily(self, request):
        """Legacy OSS daily schedule (24h interval)."""
        serializer = ScheduleDailyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        provider_id = serializer.validated_data["provider_id"]
        provider_instance = get_object_or_404(self.get_queryset(), pk=provider_id)
        with transaction.atomic():
            task = schedule_provider_scan(provider_instance)
        prowler_task = Task.objects.get(id=task.id)
        output_serializer = TaskSerializer(prowler_task)
        return Response(
            data=output_serializer.data,
            status=status.HTTP_202_ACCEPTED,
            headers={
                "Content-Location": reverse(
                    "task-detail", kwargs={"pk": prowler_task.id}
                )
            },
        )


ScheduleViewSet.authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
