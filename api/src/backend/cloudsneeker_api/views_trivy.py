"""ViewSets for the Cloudsneeker Trivy Hub."""

from api.base_views import BaseRLSViewSet
from api.rbac.permissions import Permissions
from cloudsneeker_api.models import TrivyRun, TrivyTarget
from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.serializers_trivy import (
    TrivyRunSerializer,
    TrivyTargetSerializer,
    TrivyTargetWriteSerializer,
)
from cloudsneeker_api.services.trivy import TrivyHubError, enqueue_trivy_run
from cloudsneeker_api.services.trivy_schedule import delete_target_schedule
from django_filters import rest_framework as filters
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.parsers import JSONParser
from rest_framework.response import Response


class TrivyTargetFilter(filters.FilterSet):
    mode = filters.CharFilter()
    provider = filters.UUIDFilter(field_name="provider_id")
    schedule_enabled = filters.BooleanFilter()

    class Meta:
        model = TrivyTarget
        fields = ["mode", "provider", "schedule_enabled"]


class TrivyRunFilter(filters.FilterSet):
    status = filters.CharFilter()
    target = filters.UUIDFilter(field_name="target_id")
    provider = filters.UUIDFilter(field_name="provider_id")
    trigger = filters.CharFilter()

    class Meta:
        model = TrivyRun
        fields = ["status", "target", "provider", "trigger"]


@extend_schema_view(
    list=extend_schema(tags=["Trivy"], summary="List Trivy Hub targets"),
    retrieve=extend_schema(tags=["Trivy"], summary="Get a Trivy Hub target"),
    create=extend_schema(tags=["Trivy"], summary="Create a Trivy Hub target"),
    partial_update=extend_schema(tags=["Trivy"], summary="Update a Trivy Hub target"),
    destroy=extend_schema(tags=["Trivy"], summary="Delete a Trivy Hub target"),
)
class TrivyTargetViewSet(BaseRLSViewSet):
    """CRUD for Trivy Hub targets plus scan enqueue."""

    queryset = TrivyTarget.objects.all()
    serializer_class = TrivyTargetSerializer
    filterset_class = TrivyTargetFilter
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    search_fields = ["name", "description"]
    ordering = ["-inserted_at"]
    ordering_fields = ["name", "mode", "inserted_at", "updated_at", "next_run_at"]
    required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        return (
            TrivyTarget.objects.filter(tenant_id=self.request.tenant_id)
            .select_related("provider")
            .all()
        )

    def get_serializer_class(self):
        if self.action in ("create", "partial_update"):
            return TrivyTargetWriteSerializer
        return TrivyTargetSerializer

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["tenant_id"] = self.request.tenant_id
        return context

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        target = serializer.save()
        target = TrivyTarget.objects.select_related("provider").get(pk=target.pk)
        return Response(
            TrivyTargetSerializer(
                target, context=self.get_serializer_context()
            ).data,
            status=status.HTTP_201_CREATED,
        )

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        target = serializer.save()
        target = TrivyTarget.objects.select_related("provider").get(pk=target.pk)
        return Response(
            TrivyTargetSerializer(
                target, context=self.get_serializer_context()
            ).data
        )

    def perform_destroy(self, instance):
        target_id = str(instance.id)
        super().perform_destroy(instance)
        delete_target_schedule(target_id)

    @action(
        detail=True,
        methods=["post"],
        url_path="scan",
        parser_classes=[LenientJSONAPIParser, JSONParser],
    )
    def scan(self, request, pk=None):
        """Enqueue a Trivy Hub scan for this target."""
        target = self.get_object()
        triggered_by_id = getattr(request.user, "id", None)
        try:
            run = enqueue_trivy_run(
                tenant_id=str(request.tenant_id),
                target_id=str(target.id),
                triggered_by_id=str(triggered_by_id) if triggered_by_id else None,
            )
        except TrivyHubError as exc:
            return Response(
                {"errors": [{"detail": str(exc), "code": "invalid_trivy_target"}]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        run = TrivyRun.objects.select_related("target", "provider").get(pk=run.pk)
        return Response(
            TrivyRunSerializer(run, context=self.get_serializer_context()).data,
            status=status.HTTP_202_ACCEPTED,
        )


@extend_schema_view(
    list=extend_schema(tags=["Trivy"], summary="List Trivy Hub runs"),
    retrieve=extend_schema(tags=["Trivy"], summary="Get a Trivy Hub run"),
)
class TrivyRunViewSet(BaseRLSViewSet):
    """Trivy Hub run history."""

    queryset = TrivyRun.objects.all()
    serializer_class = TrivyRunSerializer
    filterset_class = TrivyRunFilter
    http_method_names = ["get", "head", "options"]
    ordering = ["-inserted_at"]
    ordering_fields = ["inserted_at", "status", "finished_at"]
    required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        return (
            TrivyRun.objects.filter(tenant_id=self.request.tenant_id)
            .select_related("target", "provider", "triggered_by")
            .all()
        )
