"""Full ``/schedules`` API matching the Cloudsneeker UI contract.

Extends the OSS viewset, which only exposes ``POST /schedules/daily``. The
inherited ``daily`` action keeps its upstream serializer and resource type.
"""

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from api.models import Provider
from api.rbac.permissions import Permissions
from api.v1.views import ScheduleViewSet as UpstreamScheduleViewSet
from cloudsneeker_api.parsers import LenientJSONAPIParser
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
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import JSONParser
from rest_framework.response import Response


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


def _provider_resource(provider: Provider) -> dict:
    return {
        "type": "providers",
        "id": str(provider.id),
        "attributes": {
            "provider": provider.provider,
            "uid": provider.uid,
            "alias": provider.alias,
        },
    }


def _positive_int(value: str | None, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


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
class ScheduleViewSet(UpstreamScheduleViewSet):
    """JSON:API schedules keyed by provider id."""

    queryset = Provider.objects.all()
    serializer_class = ScheduleAttributesSerializer
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    required_permissions = [Permissions.MANAGE_SCANS]
    lookup_field = "pk"

    def get_queryset(self):
        return self.get_provider_queryset()

    def list(self, request, *args, **kwargs):
        # Hand-built envelopes; disable JSON:API re-wrapping (no ``data.data``).
        self.resource_name = False
        providers = self.filter_queryset(self.get_queryset())
        params = request.query_params
        configured_only = params.get("filter[configured]") == "true"
        rows = []
        for provider in providers:
            attributes = read_schedule_attributes(provider)
            if configured_only and not attributes.get("scan_enabled"):
                continue
            rows.append((provider, attributes))

        page_size = _positive_int(params.get("page[size]"), default=len(rows) or 1)
        page_number = _positive_int(params.get("page[number]"), default=1)
        pages = max(1, -(-len(rows) // page_size))
        page_rows = rows[(page_number - 1) * page_size : page_number * page_size]

        document = {
            "data": [
                _schedule_document(provider, attributes)
                for provider, attributes in page_rows
            ],
            "meta": {
                "pagination": {
                    "page": page_number,
                    "pages": pages,
                    "count": len(rows),
                }
            },
        }
        if "provider" in (params.get("include") or "").split(","):
            document["included"] = [
                _provider_resource(provider) for provider, _ in page_rows
            ]
        return Response(document)

    def retrieve(self, request, *args, **kwargs):
        self.resource_name = False
        provider = self.get_object()
        return Response(
            {"data": _schedule_document(provider, read_schedule_attributes(provider))}
        )

    def partial_update(self, request, *args, **kwargs):
        provider = self.get_object()
        payload = request.data or {}
        # Parse first: the JSON:API parser reads resource_name. Then disable
        # re-wrapping for the hand-built response.
        self.resource_name = False
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

    # The UI posts ``schedules-bulk`` documents to the ``schedules`` collection.
    @action(
        detail=False,
        methods=["post"],
        url_path="bulk",
        parser_classes=[LenientJSONAPIParser, JSONParser],
    )
    def bulk(self, request, *args, **kwargs):
        payload = request.data or {}
        self.resource_name = False
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


ScheduleViewSet.authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
