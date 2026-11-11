"""ViewSets for the Cloudsneeker Trivy Hub."""

import json

from api.base_views import BaseRLSViewSet
from api.models import Scan
from api.rbac.permissions import Permissions
from cloudsneeker_api.models import TrivyRun, TrivyTarget
from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.serializers_trivy import (
    TrivyRunSerializer,
    TrivyTargetSerializer,
    TrivyTargetWriteSerializer,
)
from cloudsneeker_api.services.brand_text import scrub_engine_text
from cloudsneeker_api.services.trivy import (
    TrivyHubError,
    enqueue_trivy_run,
    request_run_cancel,
)
from cloudsneeker_api.services.trivy_schedule import delete_target_schedule
from django.db.models import F, OuterRef, Subquery, Window
from django.db.models.functions import RowNumber
from django.http import HttpResponse
from django_filters import rest_framework as filters
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import MethodNotAllowed
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework_json_api.serializers import ValidationError


class TrivyTargetFilter(filters.FilterSet):
    mode = filters.CharFilter()
    provider = filters.UUIDFilter(field_name="provider_id")
    schedule_enabled = filters.BooleanFilter()
    application = filters.UUIDFilter(field_name="application_id")
    unassigned = filters.BooleanFilter(field_name="application", lookup_expr="isnull")

    class Meta:
        model = TrivyTarget
        fields = ["mode", "provider", "schedule_enabled", "application", "unassigned"]


LATEST_PER_TARGET_MAX = 100


class TrivyRunFilter(filters.FilterSet):
    status = filters.CharFilter()
    target = filters.UUIDFilter(field_name="target_id")
    provider = filters.UUIDFilter(field_name="provider_id")
    trigger = filters.CharFilter()
    # Target mode (repo, image, sast, ...) for the scanning centre.
    mode = filters.CharFilter(field_name="target__mode")
    archived = filters.BooleanFilter(method="filter_archived")
    latest_per_target = filters.NumberFilter(method="filter_latest_per_target")

    class Meta:
        model = TrivyRun
        fields = ["status", "target", "provider", "trigger"]

    def filter_archived(self, queryset, name, value):
        return queryset.filter(archived_at__isnull=not value)

    def filter_latest_per_target(self, queryset, name, value):
        """Keep each target's newest ``value`` runs (1-100).

        Other filters narrow the runs before they are counted, so with
        ``filter[archived]=false`` each target keeps its newest current runs.
        """
        if value != int(value) or not 1 <= value <= LATEST_PER_TARGET_MAX:
            raise ValidationError(
                f"latest_per_target must be a whole number from 1 to "
                f"{LATEST_PER_TARGET_MAX}."
            )
        return queryset.annotate(
            target_rank=Window(
                expression=RowNumber(),
                partition_by=[F("target_id")],
                order_by=[F("inserted_at").desc(), F("id").desc()],
            )
        ).filter(target_rank__lte=int(value))


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
            .select_related("provider", "application")
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
            TrivyTargetSerializer(target, context=self.get_serializer_context()).data,
            status=status.HTTP_201_CREATED,
        )

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        target = serializer.save()
        target = TrivyTarget.objects.select_related("provider").get(pk=target.pk)
        return Response(
            TrivyTargetSerializer(target, context=self.get_serializer_context()).data
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
                {
                    "errors": [
                        {
                            "detail": scrub_engine_text(str(exc)),
                            "code": "invalid_trivy_target",
                        }
                    ]
                },
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
    http_method_names = ["get", "post", "head", "options"]
    ordering = ["-inserted_at"]
    ordering_fields = ["inserted_at", "status", "finished_at"]
    required_permissions = [Permissions.MANAGE_SCANS]

    def create(self, request, *args, **kwargs):
        # Runs start from a target (``trivy-targets/{id}/scan``).
        raise MethodNotAllowed("POST")

    def perform_content_negotiation(self, request, force=False):
        # ``?format=sarif`` names a file format on the export action.
        if self.action == "export":
            force = True
        return super().perform_content_negotiation(request, force=force)

    @extend_schema(tags=["Trivy"], summary="Cancel a queued or running scan")
    @action(
        detail=True,
        methods=["post"],
        url_path="cancel",
        parser_classes=[LenientJSONAPIParser, JSONParser],
    )
    def cancel(self, request, pk=None):
        run = self.get_object()
        try:
            request_run_cancel(tenant_id=str(request.tenant_id), run_id=str(run.id))
        except TrivyHubError as exc:
            return Response(
                {"errors": [{"detail": str(exc), "code": "scan_not_cancellable"}]},
                status=status.HTTP_409_CONFLICT,
            )
        run = self.get_queryset().get(pk=run.pk)
        return Response(
            TrivyRunSerializer(run, context=self.get_serializer_context()).data,
            status=status.HTTP_202_ACCEPTED,
        )

    @extend_schema(
        tags=["Trivy"],
        summary="Download the stored scan report (json, sarif, cyclonedx, spdx-json)",
    )
    # No filter backends: the JSON:API query validation would reject the
    # ``format`` and ``index`` parameters with a 400.
    @action(detail=True, methods=["get"], url_path="export", filter_backends=[])
    def export(self, request, pk=None):
        from cloudsneeker_api.appsec import capabilities as caps
        from cloudsneeker_api.appsec import engine

        run = self.get_object()
        fmt = str(request.query_params.get("format") or "json").lower()
        allowed = caps.TARGETS.get(run.target.mode, {}).get("export_formats", ())
        if fmt not in allowed:
            return Response(
                {
                    "errors": [
                        {
                            "detail": "This format is not available for the scan.",
                            "code": "invalid_format",
                        }
                    ]
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            index = int(request.query_params.get("index") or 0)
        except ValueError:
            index = 0
        report = engine.load_report(run, index)
        if report is None:
            return Response(
                {
                    "errors": [
                        {
                            "detail": "The scan report is no longer stored.",
                            "code": "artifact_gone",
                        }
                    ]
                },
                status=status.HTTP_404_NOT_FOUND,
            )
        if fmt == "json":
            body, content_type, extension = (
                json.dumps(report).encode("utf-8"),
                "application/json",
                "json",
            )
        else:
            try:
                body = engine.convert_report(report, fmt)
            except engine.EngineError as exc:
                return Response(
                    {
                        "errors": [
                            {
                                "detail": scrub_engine_text(str(exc)),
                                "code": "conversion_failed",
                            }
                        ]
                    },
                    status=status.HTTP_502_BAD_GATEWAY,
                )
            _, content_type, extension = engine.CONVERT_FORMATS[fmt]
        response = HttpResponse(body, content_type=content_type)
        response["Content-Disposition"] = (
            f'attachment; filename="cloudsneeker-scan-{run.id}.{extension}"'
        )
        return response

    def get_queryset(self):
        return (
            TrivyRun.objects.filter(tenant_id=self.request.tenant_id)
            .select_related("target", "provider", "triggered_by")
            .annotate(
                linked_scan_state=Subquery(
                    Scan.objects.filter(id=OuterRef("scan_id")).values("state")[:1]
                )
            )
        )
