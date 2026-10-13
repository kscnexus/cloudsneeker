"""ViewSets for Cloudsneeker Alerts, Scan Configuration, and CLI Import."""

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from api.base_views import BaseRLSViewSet
from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import Finding
from api.rbac.permissions import Permissions
from cloudsneeker_api.models import AlertRecipient, AlertRule, FindingIngestion, ScanConfiguration
from cloudsneeker_api.serializers_alerts import (
    AlertRecipientSerializer,
    AlertRuleSerializer,
    AlertRuleWriteSerializer,
)
from cloudsneeker_api.serializers_scan_config import (
    ScanConfigurationSerializer,
    ScanConfigurationWriteSerializer,
)
from cloudsneeker_api.services.alert_conditions import preview_condition
from cloudsneeker_api.services.ocsf_import import parse_ocsf_payload
from django.utils import timezone
from django_filters import rest_framework as filters
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import permissions, status
from rest_framework.decorators import action
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView


class ScanConfigurationFilter(filters.FilterSet):
    class Meta:
        model = ScanConfiguration
        fields = {
            "name": ["exact", "icontains"],
        }


@extend_schema_view(
    list=extend_schema(tags=["Scan Configurations"], summary="List scan configurations"),
    retrieve=extend_schema(tags=["Scan Configurations"], summary="Get a scan configuration"),
    create=extend_schema(tags=["Scan Configurations"], summary="Create a scan configuration"),
    partial_update=extend_schema(
        tags=["Scan Configurations"], summary="Update a scan configuration"
    ),
    destroy=extend_schema(tags=["Scan Configurations"], summary="Delete a scan configuration"),
)
class ScanConfigurationViewSet(BaseRLSViewSet):
    queryset = ScanConfiguration.objects.all()
    serializer_class = ScanConfigurationSerializer
    filterset_class = ScanConfigurationFilter
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    search_fields = ["name"]
    ordering = ["-inserted_at"]
    ordering_fields = ["name", "inserted_at", "updated_at"]
    required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        return (
            ScanConfiguration.objects.filter(tenant_id=self.request.tenant_id)
            .prefetch_related("providers")
            .all()
        )

    def get_serializer_class(self):
        if self.action in ("create", "partial_update"):
            return ScanConfigurationWriteSerializer
        return ScanConfigurationSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        config = serializer.save()
        return Response(
            ScanConfigurationSerializer(config, context=self.get_serializer_context()).data,
            status=status.HTTP_201_CREATED,
        )

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        config = serializer.save()
        return Response(
            ScanConfigurationSerializer(config, context=self.get_serializer_context()).data
        )


class AlertRuleFilter(filters.FilterSet):
    enabled = filters.BooleanFilter()
    trigger = filters.CharFilter()
    search = filters.CharFilter(field_name="name", lookup_expr="icontains")

    class Meta:
        model = AlertRule
        fields = ["enabled", "trigger"]


@extend_schema_view(
    list=extend_schema(tags=["Alerts"], summary="List alert rules"),
    retrieve=extend_schema(tags=["Alerts"], summary="Get an alert rule"),
    create=extend_schema(tags=["Alerts"], summary="Create an alert rule"),
    partial_update=extend_schema(tags=["Alerts"], summary="Update an alert rule"),
    destroy=extend_schema(tags=["Alerts"], summary="Delete an alert rule"),
)
class AlertRuleViewSet(BaseRLSViewSet):
    queryset = AlertRule.objects.all()
    serializer_class = AlertRuleSerializer
    filterset_class = AlertRuleFilter
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    search_fields = ["name", "description"]
    ordering = ["-inserted_at"]
    ordering_fields = ["name", "enabled", "inserted_at", "updated_at"]
    required_permissions = []

    def get_queryset(self):
        return (
            AlertRule.objects.filter(tenant_id=self.request.tenant_id)
            .prefetch_related("recipients")
            .select_related("created_by")
        )

    def get_serializer_class(self):
        if self.action in ("create", "partial_update"):
            return AlertRuleWriteSerializer
        return AlertRuleSerializer

    def get_permissions(self):
        if self.action in ("create", "partial_update", "destroy", "seed", "preview"):
            self.required_permissions = [Permissions.MANAGE_SCANS]
        else:
            self.required_permissions = []
        return super().get_permissions()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        rule = serializer.save()
        return Response(
            AlertRuleSerializer(rule, context=self.get_serializer_context()).data,
            status=status.HTTP_201_CREATED,
        )

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        rule = serializer.save()
        return Response(
            AlertRuleSerializer(rule, context=self.get_serializer_context()).data
        )

    @action(detail=False, methods=["post"], url_path="seed")
    def seed(self, request, *args, **kwargs):
        payload = request.data or {}
        filter_bag = payload.get("filter_bag") or {}
        if not isinstance(filter_bag, dict):
            filter_bag = {}
        severity = (
            filter_bag.get("severity")
            or filter_bag.get("filter[severity]")
            or filter_bag.get("filter[severity__in]")
        )
        if isinstance(severity, str):
            severity = [part.strip() for part in severity.split(",") if part.strip()]
        condition = {
            "op": "count_gte",
            "filter": {"severity": severity or ["critical", "high"]},
            "value": 1,
        }
        name = "Findings alert"
        if severity:
            name = f"{', '.join(severity)} findings"
        return Response(
            {
                "data": {
                    "id": "seeded-rule",
                    "type": "alert-rule-seedings",
                    "attributes": {
                        "name": name[:100],
                        "description": "Seeded from findings filters.",
                        "enabled": True,
                        "trigger": AlertRule.Trigger.AFTER_SCAN,
                        "condition": condition,
                        "schema_version": 1,
                        "recipient_emails": [],
                        "slack_channels": [],
                    },
                }
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=False, methods=["post"], url_path="preview")
    def preview(self, request, *args, **kwargs):
        payload = request.data or {}
        condition = payload.get("condition") or {}
        queryset = Finding.all_objects.filter(tenant_id=request.tenant_id)
        preview = preview_condition(queryset, condition)
        return Response(
            {
                "data": {
                    "id": "preview",
                    "type": "alert-rule-previews",
                    "attributes": preview,
                }
            }
        )


class AlertRecipientViewSet(BaseRLSViewSet):
    queryset = AlertRecipient.objects.all()
    serializer_class = AlertRecipientSerializer
    http_method_names = ["get", "head", "options"]
    search_fields = ["email"]
    ordering = ["email"]
    required_permissions = []

    def get_queryset(self):
        return AlertRecipient.objects.filter(tenant_id=self.request.tenant_id)


class AlertSlackChannelsView(APIView):
    """Return Slack channels eligible for alert destinations."""

    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        tenant_id = request.auth.get("tenant_id") if request.auth else None
        return Response(
            {
                "data": {
                    "type": "alert-slack-channels",
                    "id": str(tenant_id or "unknown"),
                    "attributes": {
                        "connected": None,
                        "workspace_name": None,
                        "channels": [],
                    },
                }
            }
        )


class AlertRecipientConfirmView(APIView):
    """Confirm an alert recipient from an emailed token."""

    authentication_classes = []
    permission_classes = []

    def get(self, request, *args, **kwargs):
        token = request.query_params.get("token", "")
        recipient = (
            AlertRecipient.objects.using(MainRouter.admin_db)
            .filter(confirmation_token=token)
            .first()
        )
        if not recipient:
            return Response(
                {"errors": [{"detail": "Invalid or expired confirmation token."}]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        with rls_transaction(str(recipient.tenant_id)):
            recipient.status = AlertRecipient.Status.CONFIRMED
            recipient.confirmed_at = timezone.now()
            recipient.save(update_fields=["status", "confirmed_at", "updated_at"])
        return Response({"data": {"type": "alert-recipients", "id": str(recipient.id)}})


class AlertRecipientUnsubscribeView(APIView):
    """Unsubscribe an alert recipient from an emailed token."""

    authentication_classes = []
    permission_classes = []

    def get(self, request, *args, **kwargs):
        token = request.query_params.get("token", "")
        recipient = (
            AlertRecipient.objects.using(MainRouter.admin_db)
            .filter(unsubscribe_token=token)
            .first()
        )
        if not recipient:
            return Response(
                {"errors": [{"detail": "Invalid unsubscribe token."}]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        with rls_transaction(str(recipient.tenant_id)):
            recipient.status = AlertRecipient.Status.UNSUBSCRIBED
            recipient.unsubscribed_at = timezone.now()
            recipient.save(update_fields=["status", "unsubscribed_at", "updated_at"])
        return Response({"data": {"type": "alert-recipients", "id": str(recipient.id)}})


class IngestionViewSet(BaseRLSViewSet):
    """Accept OCSF report uploads and expose import job status."""

    queryset = FindingIngestion.objects.all()
    http_method_names = ["get", "post", "head", "options"]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        return FindingIngestion.objects.filter(tenant_id=self.request.tenant_id)

    def _document(self, ingestion: FindingIngestion) -> dict:
        return {
            "type": "ingestions",
            "id": str(ingestion.id),
            "attributes": {
                "status": ingestion.status,
                "summary": {
                    "total": ingestion.total_records,
                    "processed": ingestion.processed_records,
                    "invalid": ingestion.invalid_records,
                },
            },
        }

    def retrieve(self, request, *args, **kwargs):
        ingestion = self.get_object()
        return Response({"data": self._document(ingestion)})

    def create(self, request, *args, **kwargs):
        upload = request.FILES.get("file") or request.FILES.get("report")
        if upload is None:
            return Response(
                {
                    "errors": [
                        {
                            "code": "invalid",
                            "detail": "The report is not a valid Cloudsneeker OCSF finding report.",
                        }
                    ]
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        if upload.size and upload.size > 50 * 1024 * 1024:
            return Response(
                {
                    "errors": [
                        {
                            "code": "file_too_large",
                            "detail": "The selected file exceeds the allowed upload size.",
                        }
                    ]
                },
                status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )

        raw = upload.read()
        try:
            records = parse_ocsf_payload(raw)
        except Exception:  # noqa: BLE001
            return Response(
                {
                    "errors": [
                        {
                            "code": "invalid",
                            "detail": "The report is not a valid Cloudsneeker OCSF finding report.",
                        }
                    ]
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        ingestion = FindingIngestion.objects.create(
            tenant_id=request.tenant_id,
            status=FindingIngestion.Status.PENDING,
            original_filename=getattr(upload, "name", "")[:255],
            payload=records,
            total_records=len(records),
            created_by=request.user if request.user.is_authenticated else None,
        )
        from cloudsneeker_api.tasks import process_finding_ingestion_task

        process_finding_ingestion_task.delay(
            tenant_id=str(request.tenant_id),
            ingestion_id=str(ingestion.id),
        )
        return Response(
            {"data": self._document(ingestion)},
            status=status.HTTP_202_ACCEPTED,
        )
