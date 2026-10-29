"""Reporting engine API: report types, runs, schedules, and share links."""

from __future__ import annotations

import os

from api.base_views import BaseRLSViewSet
from api.rbac.permissions import Permissions
from cloudsneeker_api.models import (
    JSON_API_TYPE_PREFIX,
    ReportRun,
    ReportSchedule,
    ReportShareLink,
)
from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.reports.access import (
    ReportAccessError,
    filter_runs_for_role,
    params_visible_to_role,
    scope_params_to_role,
)
from cloudsneeker_api.reports.catalog import (
    FORMAT_CONTENT_TYPES,
    REPORT_TYPES,
    ReportParamsError,
    report_filename,
)
from cloudsneeker_api.reports.runs import (
    ReportRunError,
    artifact_path,
    delete_run_artifacts,
    enqueue_report_run,
    read_report_json,
)
from cloudsneeker_api.reports.schedule import (
    ReportScheduleError,
    delete_report_schedule_task,
    sync_report_schedule,
)
from cloudsneeker_api.reports.share import (
    ShareLinkError,
    create_share_link,
    resolve_share_token,
    revoke_share_link,
)
from cloudsneeker_api.serializers_reports import (
    ReportRunCreateSerializer,
    ReportRunSerializer,
    ReportScheduleSerializer,
    ReportScheduleWriteSerializer,
    ReportShareLinkCreateSerializer,
    ReportShareLinkSerializer,
    ReportTypeSerializer,
)
from django.http import FileResponse
from django_filters import rest_framework as filters
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework.views import APIView

REPORT_TYPE_RESOURCE = f"{JSON_API_TYPE_PREFIX}report-types"
SHARED_REPORT_RESOURCE = f"{JSON_API_TYPE_PREFIX}shared-reports"


def _error(detail: str, code: str, http_status: int) -> Response:
    # The JSON:API renderer wraps 4xx/5xx data in ``{"errors": data}`` itself,
    # so pass the error objects as a list to keep a single envelope.
    return Response(
        [{"detail": detail, "code": code, "status": str(http_status)}],
        status=http_status,
    )


class ReportTypeViewSet(BaseRLSViewSet):
    """Static catalog of report types."""

    serializer_class = ReportTypeSerializer
    http_method_names = ["get", "head", "options"]
    required_permissions = []
    # Hand-built JSON:API documents; skip renderer re-wrapping.
    resource_name = False
    pagination_class = None

    def get_queryset(self):
        return ReportRun.objects.none()

    @staticmethod
    def _document(report_type_id: str) -> dict:
        return {
            "type": REPORT_TYPE_RESOURCE,
            "id": report_type_id,
            "attributes": REPORT_TYPES[report_type_id].to_dict(),
        }

    @extend_schema(tags=["Reports"], summary="List report types")
    def list(self, request, *args, **kwargs):
        return Response({"data": [self._document(key) for key in REPORT_TYPES]})

    @extend_schema(tags=["Reports"], summary="Get a report type")
    def retrieve(self, request, *args, **kwargs):
        key = kwargs.get("pk")
        if key not in REPORT_TYPES:
            raise NotFound("Unknown report type.")
        return Response({"data": self._document(key)})


class ReportRunFilter(filters.FilterSet):
    report_type = filters.CharFilter()
    status = filters.CharFilter()
    trigger = filters.CharFilter()
    schedule = filters.UUIDFilter(field_name="schedule_id")

    class Meta:
        model = ReportRun
        fields = ["report_type", "status", "trigger", "schedule"]


class _ReportVisibilityMixin:
    """Queryset scoping shared by the run, schedule, and share link views."""

    def _role_scoped(self, queryset):
        return filter_runs_for_role(queryset, self.user_role, self.request.user.id)

    def _scoped_params(self, params: dict) -> dict:
        try:
            return scope_params_to_role(params, self.user_role)
        except ReportAccessError as exc:
            raise PermissionDenied(str(exc)) from exc


@extend_schema_view(
    list=extend_schema(tags=["Reports"], summary="List report runs"),
    retrieve=extend_schema(tags=["Reports"], summary="Get a report run"),
    create=extend_schema(tags=["Reports"], summary="Generate a report"),
    destroy=extend_schema(tags=["Reports"], summary="Delete a report run"),
)
class ReportRunViewSet(_ReportVisibilityMixin, BaseRLSViewSet):
    """Generate reports and download their artifacts.

    Visibility follows findings: any user may generate a report over the
    providers they can see; limited roles only see their own runs and runs
    whose providers are all visible to them.
    """

    queryset = ReportRun.objects.all()
    serializer_class = ReportRunSerializer
    filterset_class = ReportRunFilter
    http_method_names = ["get", "post", "delete", "head", "options"]
    ordering = ["-inserted_at"]
    ordering_fields = ["inserted_at", "finished_at", "status", "report_type"]
    required_permissions = []

    def get_queryset(self):
        queryset = ReportRun.objects.filter(tenant_id=self.request.tenant_id)
        return self._role_scoped(queryset)

    def get_serializer_class(self):
        if self.action == "create":
            return ReportRunCreateSerializer
        return ReportRunSerializer

    def perform_content_negotiation(self, request, force=False):
        # ``?format=pdf`` is the download contract; never let DRF's format
        # override turn it into a renderer lookup (404).
        if self.action == "download":
            force = True
        return super().perform_content_negotiation(request, force=force)

    def _run(self, pk) -> ReportRun:
        run = self.get_queryset().filter(pk=pk).first()
        if run is None:
            raise NotFound("Report run not found.")
        return run

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        params = self._scoped_params(serializer.validated_data["params"])
        try:
            run = enqueue_report_run(
                tenant_id=str(request.tenant_id),
                report_type=serializer.validated_data["report_type"],
                params=params,
                formats=serializer.validated_data["formats"],
                created_by_id=str(request.user.id),
            )
        except ReportParamsError as exc:
            return _error(str(exc), "invalid_report_params", status.HTTP_400_BAD_REQUEST)
        return Response(
            ReportRunSerializer(run, context=self.get_serializer_context()).data,
            status=status.HTTP_202_ACCEPTED,
        )

    def perform_destroy(self, instance):
        tenant_id, run_id = str(instance.tenant_id), str(instance.id)
        super().perform_destroy(instance)
        delete_run_artifacts(tenant_id, run_id)

    @extend_schema(
        tags=["Reports"],
        summary="Download a report artifact",
        responses={
            200: OpenApiResponse(description="The report file (PDF, XLSX, CSV or JSON)")
        },
    )
    @action(detail=True, methods=["get"], url_path="download")
    def download(self, request, pk=None):
        """Stream ``?format=pdf|xlsx|csv|json`` with a branded filename."""
        run = self._run(pk)
        fmt = str(
            request.query_params.get("format")
            or request.query_params.get("file_format")
            or "pdf"
        ).lower()
        if fmt not in FORMAT_CONTENT_TYPES:
            return _error("Unknown format.", "invalid_format", status.HTTP_400_BAD_REQUEST)
        try:
            path = artifact_path(run, fmt)
        except ReportRunError as exc:
            return _error(str(exc), "report_unavailable", status.HTTP_404_NOT_FOUND)
        filename = report_filename(run.report_type, fmt, run.finished_at or run.inserted_at)
        response = FileResponse(
            open(path, "rb"),  # noqa: SIM115 - FileResponse closes the file
            as_attachment=True,
            filename=filename,
            content_type=FORMAT_CONTENT_TYPES[fmt],
        )
        response["Content-Length"] = str(os.path.getsize(path))
        return response

    @extend_schema(
        tags=["Reports"],
        summary="Get the interactive report payload",
        responses={200: OpenApiResponse(description="Report payload")},
    )
    @action(detail=True, methods=["get"], url_path="data", url_name="data")
    def report_data(self, request, pk=None):
        """Return the stored report JSON for the in-app report page."""
        self.resource_name = False
        run = self._run(pk)
        try:
            payload = read_report_json(run)
        except ReportRunError as exc:
            return _error(str(exc), "report_unavailable", status.HTTP_404_NOT_FOUND)
        return Response(
            {
                "data": {
                    "type": f"{JSON_API_TYPE_PREFIX}report-data",
                    "id": str(run.id),
                    "attributes": payload,
                }
            }
        )

    @extend_schema(
        tags=["Reports"],
        summary="Create or list share links",
        request=ReportShareLinkCreateSerializer,
        responses={
            200: OpenApiResponse(description="Share links for the report run"),
            201: OpenApiResponse(description="The new share link with its one-time token"),
        },
    )
    @action(
        detail=True,
        methods=["get", "post"],
        url_path="share-links",
        parser_classes=[LenientJSONAPIParser, JSONParser],
    )
    def shares(self, request, pk=None):
        """POST creates an expiring public link (token returned once)."""
        body = request.data if request.method == "POST" else {}
        self.resource_name = False
        run = self._run(pk)
        if request.method == "GET":
            links = ReportShareLink.objects.filter(
                tenant_id=request.tenant_id, report_run_id=run.id
            ).order_by("-inserted_at")
            return Response(
                {
                    "data": [
                        _share_document(link, self.get_serializer_context())
                        for link in links
                    ]
                }
            )
        if not self.user_role.manage_scans:
            raise PermissionDenied("Sharing reports requires the manage scans permission.")
        if not params_visible_to_role(run.params, self.user_role):
            raise PermissionDenied("This report covers providers you cannot see.")
        serializer = ReportShareLinkCreateSerializer(data=body or {})
        serializer.is_valid(raise_exception=True)
        try:
            link, token = create_share_link(
                tenant_id=str(request.tenant_id),
                run=run,
                created_by_id=str(request.user.id),
                expires_in_hours=serializer.validated_data.get("expires_in_hours"),
            )
        except ShareLinkError as exc:
            return _error(str(exc), exc.code, status.HTTP_400_BAD_REQUEST)
        document = _share_document(link, self.get_serializer_context())
        # The raw token is only ever returned here.
        document["attributes"]["token"] = token
        return Response({"data": document}, status=status.HTTP_201_CREATED)


def _share_document(link: ReportShareLink, context: dict) -> dict:
    attributes = dict(ReportShareLinkSerializer(link, context=context).data)
    attributes.pop("id", None)
    attributes.pop("type", None)
    return {
        "type": f"{JSON_API_TYPE_PREFIX}report-share-links",
        "id": str(link.id),
        "attributes": attributes,
    }


class ReportShareLinkFilter(filters.FilterSet):
    report_run = filters.UUIDFilter(field_name="report_run_id")

    class Meta:
        model = ReportShareLink
        fields = ["report_run"]


@extend_schema_view(
    list=extend_schema(tags=["Reports"], summary="List report share links"),
    retrieve=extend_schema(tags=["Reports"], summary="Get a report share link"),
)
class ReportShareLinkViewSet(_ReportVisibilityMixin, BaseRLSViewSet):
    """Share link management; tokens are never returned after creation."""

    queryset = ReportShareLink.objects.all()
    serializer_class = ReportShareLinkSerializer
    filterset_class = ReportShareLinkFilter
    http_method_names = ["get", "post", "head", "options"]
    ordering = ["-inserted_at"]
    ordering_fields = ["inserted_at", "expires_at"]
    required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        runs = self._role_scoped(ReportRun.objects.filter(tenant_id=self.request.tenant_id))
        return ReportShareLink.objects.filter(
            tenant_id=self.request.tenant_id, report_run__in=runs
        )

    @extend_schema(tags=["Reports"], summary="Revoke a report share link")
    @action(
        detail=True,
        methods=["post"],
        url_path="revoke",
        parser_classes=[LenientJSONAPIParser, JSONParser],
    )
    def revoke(self, request, pk=None):
        link = self.get_queryset().filter(pk=pk).first()
        if link is None:
            raise NotFound("Share link not found.")
        link = revoke_share_link(link)
        return Response(
            ReportShareLinkSerializer(link, context=self.get_serializer_context()).data
        )


class ReportScheduleFilter(filters.FilterSet):
    report_type = filters.CharFilter()
    enabled = filters.BooleanFilter()

    class Meta:
        model = ReportSchedule
        fields = ["report_type", "enabled"]


@extend_schema_view(
    list=extend_schema(tags=["Reports"], summary="List report schedules"),
    retrieve=extend_schema(tags=["Reports"], summary="Get a report schedule"),
    create=extend_schema(tags=["Reports"], summary="Create a report schedule"),
    partial_update=extend_schema(tags=["Reports"], summary="Update a report schedule"),
    destroy=extend_schema(tags=["Reports"], summary="Delete a report schedule"),
)
class ReportScheduleViewSet(_ReportVisibilityMixin, BaseRLSViewSet):
    """CRUD for scheduled, emailed reports (synced to Celery Beat)."""

    queryset = ReportSchedule.objects.all()
    serializer_class = ReportScheduleSerializer
    filterset_class = ReportScheduleFilter
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    search_fields = ["name"]
    ordering = ["name"]
    ordering_fields = ["name", "inserted_at", "next_run_at", "last_run_at"]
    required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        return self._role_scoped(
            ReportSchedule.objects.filter(tenant_id=self.request.tenant_id)
        )

    def get_serializer_class(self):
        if self.action in ("create", "partial_update"):
            return ReportScheduleWriteSerializer
        return ReportScheduleSerializer

    def _synced(self, schedule: ReportSchedule) -> ReportSchedule | Response:
        try:
            return sync_report_schedule(schedule)
        except ReportScheduleError as exc:
            return _error(str(exc), "invalid_schedule", status.HTTP_400_BAD_REQUEST)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = dict(serializer.validated_data)
        data["params"] = self._scoped_params(data["params"])
        schedule = ReportSchedule.objects.create(
            tenant_id=request.tenant_id, created_by_id=request.user.id, **data
        )
        result = self._synced(schedule)
        if isinstance(result, Response):
            return result
        return Response(
            ReportScheduleSerializer(result, context=self.get_serializer_context()).data,
            status=status.HTTP_201_CREATED,
        )

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        data = dict(serializer.validated_data)
        data["params"] = self._scoped_params(data["params"])
        for attr, value in data.items():
            setattr(instance, attr, value)
        instance.save()
        result = self._synced(instance)
        if isinstance(result, Response):
            return result
        return Response(
            ReportScheduleSerializer(result, context=self.get_serializer_context()).data
        )

    def perform_destroy(self, instance):
        schedule_id = str(instance.id)
        super().perform_destroy(instance)
        delete_report_schedule_task(schedule_id)


class SharedReportThrottle(SimpleRateThrottle):
    """Per-IP limit on the public share endpoint (``REPORT_SHARE_THROTTLE``)."""

    scope = "cloudsneeker-shared-reports"

    def get_rate(self):
        return os.environ.get("REPORT_SHARE_THROTTLE", "60/min")

    def get_cache_key(self, request, view):
        return self.cache_format % {
            "scope": self.scope,
            "ident": self.get_ident(request),
        }


class SharedReportView(APIView):
    """Public, unauthenticated read of one shared report's JSON payload.

    The response carries only the report payload (no tenant, user, or run
    metadata). Unknown, expired, and revoked tokens get the same status code
    family so the endpoint does not reveal which tokens ever existed.
    """

    authentication_classes = []
    permission_classes = []
    throttle_classes = [SharedReportThrottle]
    resource_name = False

    @extend_schema(
        tags=["Reports"],
        summary="Read a shared report",
        auth=[],
        responses={200: OpenApiResponse(description="Shared report payload")},
    )
    def get(self, request, token: str, *args, **kwargs):
        try:
            _, payload = resolve_share_token(token)
        except ShareLinkError as exc:
            http_status = (
                status.HTTP_410_GONE
                if exc.code in ("expired", "revoked")
                else status.HTTP_404_NOT_FOUND
            )
            return _error(str(exc), exc.code, http_status)
        response = Response(
            {
                "data": {
                    "type": SHARED_REPORT_RESOURCE,
                    "id": "shared",
                    "attributes": payload,
                }
            }
        )
        response["Cache-Control"] = "no-store"
        response["X-Robots-Tag"] = "noindex, nofollow"
        response["Referrer-Policy"] = "no-referrer"
        return response
