"""Audit log API: list, retrieve, and CSV export of ``AuditEvent`` rows.

Append-only: there is no create, update, or delete route. Reading needs the
upstream ``manage_account`` permission (tenant administrators).
"""

from __future__ import annotations

import csv
import uuid
from datetime import UTC, datetime, time, timedelta

from api.base_views import BaseRLSViewSet
from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.filters import CharInFilter
from api.rbac.permissions import Permissions
from cloudsneeker_api.models import AuditEvent
from cloudsneeker_api.serializers_audit import AuditEventSerializer
from django.http import StreamingHttpResponse
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from django_filters import rest_framework as filters
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

EXPORT_MAX_ROWS = 100_000
EXPORT_CHUNK_SIZE = 2_000
EXPORT_FORMATS = ("csv",)
EXPORT_COLUMNS = [
    ("inserted_at", "time"),
    ("actor_email", "actor_email"),
    ("actor_id", "actor_id"),
    ("action", "action"),
    ("outcome", "outcome"),
    ("target_type", "target_type"),
    ("target_id", "target_id"),
    ("target_label", "target_label"),
    ("ip_address", "ip_address"),
    ("user_agent", "user_agent"),
    ("method", "method"),
    ("path", "path"),
    ("status_code", "status_code"),
    ("request_id", "request_id"),
]
# Spreadsheet apps evaluate cells that start with these characters.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _error(detail: str, code: str, http_status: int) -> Response:
    # The JSON:API renderer wraps error data in ``{"errors": ...}`` itself.
    return Response(
        [{"detail": detail, "code": code, "status": str(http_status)}],
        status=http_status,
    )


def _parse_bound(value: str, *, end: bool):
    """A datetime or a date; a date as an upper bound covers the whole day."""
    parsed = parse_datetime(value)
    if parsed is not None:
        if timezone.is_naive(parsed):
            parsed = timezone.make_aware(parsed, UTC)
        return parsed, False
    day = parse_date(value)
    if day is None:
        return None, False
    start = datetime.combine(day, time.min, tzinfo=UTC)
    return (start + timedelta(days=1), True) if end else (start, False)


class AuditEventFilter(filters.FilterSet):
    action = filters.CharFilter(field_name="action")
    action__startswith = filters.CharFilter(
        field_name="action", lookup_expr="startswith"
    )
    action__in = CharInFilter(field_name="action", lookup_expr="in")
    actor = filters.CharFilter(method="filter_actor")
    actor_email = filters.CharFilter(field_name="actor_email", lookup_expr="iexact")
    actor_email__icontains = filters.CharFilter(
        field_name="actor_email", lookup_expr="icontains"
    )
    outcome = filters.ChoiceFilter(choices=AuditEvent.Outcome.choices)
    target_type = filters.CharFilter(field_name="target_type")
    target_id = filters.CharFilter(field_name="target_id")
    inserted_at__gte = filters.CharFilter(method="filter_inserted_gte")
    inserted_at__lte = filters.CharFilter(method="filter_inserted_lte")

    class Meta:
        model = AuditEvent
        fields = []

    def filter_actor(self, queryset, name, value):
        """Actor user id (UUID) or part of the actor email."""
        try:
            return queryset.filter(actor_id=uuid.UUID(str(value)))
        except ValueError:
            return queryset.filter(actor_email__icontains=value)

    def filter_inserted_gte(self, queryset, name, value):
        bound, _ = _parse_bound(value, end=False)
        return queryset if bound is None else queryset.filter(inserted_at__gte=bound)

    def filter_inserted_lte(self, queryset, name, value):
        bound, exclusive = _parse_bound(value, end=True)
        if bound is None:
            return queryset
        if exclusive:
            return queryset.filter(inserted_at__lt=bound)
        return queryset.filter(inserted_at__lte=bound)


def plain_filter_params(query_params) -> dict:
    """``filter[name]=value`` and ``name=value`` query params as filter data."""
    data = {}
    for key in query_params:
        value = query_params.get(key)
        if key.startswith("filter[") and key.endswith("]"):
            data[key[len("filter[") : -1]] = value
        elif key in AuditEventFilter.base_filters:
            data.setdefault(key, value)
    return data


def _csv_cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    text = str(value)
    if text.startswith(_CSV_FORMULA_PREFIXES):
        return f"'{text}"
    return text


class _Echo:
    """File-like object whose ``write`` returns the line for streaming."""

    def write(self, value):
        return value


def stream_audit_csv(tenant_id: str, filter_data: dict):
    """Yield CSV lines for the tenant's filtered events, newest first.

    The rows are read in their own RLS transaction because a streaming body
    is consumed after the view (and its transaction) has returned.
    """
    writer = csv.writer(_Echo())
    yield writer.writerow([header for _, header in EXPORT_COLUMNS])
    fields = [name for name, _ in EXPORT_COLUMNS]
    with rls_transaction(tenant_id, using=MainRouter.default_db):
        queryset = AuditEvent.objects.using(MainRouter.default_db).filter(
            tenant_id=tenant_id
        )
        queryset = AuditEventFilter(filter_data, queryset=queryset).qs
        rows = queryset.order_by("-inserted_at").values_list(*fields)[:EXPORT_MAX_ROWS]
        for row in rows.iterator(chunk_size=EXPORT_CHUNK_SIZE):
            yield writer.writerow([_csv_cell(value) for value in row])


@extend_schema_view(
    list=extend_schema(tags=["Audit log"], summary="List audit events"),
    retrieve=extend_schema(tags=["Audit log"], summary="Get an audit event"),
)
class AuditEventViewSet(BaseRLSViewSet):
    """Read-only access to the tenant's user-action audit log."""

    queryset = AuditEvent.objects.all()
    serializer_class = AuditEventSerializer
    filterset_class = AuditEventFilter
    http_method_names = ["get", "head", "options"]
    ordering = ["-inserted_at"]
    ordering_fields = ["inserted_at", "action", "outcome", "actor_email", "target_type"]
    required_permissions = [Permissions.MANAGE_ACCOUNT]

    def get_queryset(self):
        return AuditEvent.objects.filter(tenant_id=self.request.tenant_id)

    def perform_content_negotiation(self, request, force=False):
        # ``?format=csv`` is the export contract, not a renderer lookup.
        if self.action == "export":
            force = True
        return super().perform_content_negotiation(request, force=force)

    @extend_schema(
        tags=["Audit log"],
        summary="Export audit events as CSV",
        description=(
            "Streams the filtered audit events (same filters as the list, "
            f"newest first, at most {EXPORT_MAX_ROWS} rows) as a CSV file."
        ),
        parameters=[
            OpenApiParameter(
                name="format",
                description="Export format; only `csv` is supported.",
                required=False,
                type=str,
            )
        ],
        responses={200: OpenApiResponse(description="CSV file of audit events")},
    )
    @action(detail=False, methods=["get"], url_path="export", url_name="export")
    def export(self, request):
        fmt = str(request.query_params.get("format") or "csv").lower()
        if fmt not in EXPORT_FORMATS:
            return _error(
                "Unknown format.", "invalid_format", status.HTTP_400_BAD_REQUEST
            )
        filter_data = plain_filter_params(request.query_params)
        filterset = AuditEventFilter(filter_data, queryset=AuditEvent.objects.none())
        if not filterset.is_valid():
            return _error(
                "Invalid audit log filter.",
                "invalid_filter",
                status.HTTP_400_BAD_REQUEST,
            )
        filename = f"audit-log-{timezone.now().strftime('%Y-%m-%d')}.csv"
        response = StreamingHttpResponse(
            stream_audit_csv(str(request.tenant_id), filter_data),
            content_type="text/csv; charset=utf-8",
        )
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        response["Cache-Control"] = "no-store"
        return response
