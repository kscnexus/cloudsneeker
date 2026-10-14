"""ViewSets for Cloudsneeker Alerts, Scan Configuration, and CLI Import."""

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from api.base_views import BaseRLSViewSet
from api.db_router import MainRouter
from api.db_utils import rls_transaction
from api.models import Finding
from api.rbac.permissions import Permissions
from cloudsneeker_api.models import (
    AlertRecipient,
    AlertRule,
    CustodianPolicy,
    CustodianRun,
    FindingIngestion,
    ScanConfiguration,
)
from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.serializers_alerts import (
    AlertRecipientSerializer,
    AlertRuleSerializer,
    AlertRuleWriteSerializer,
)
from cloudsneeker_api.serializers_custodian import (
    CustodianPolicySerializer,
    CustodianPolicyWriteSerializer,
    CustodianRunSerializer,
    CustodianScheduleBulkSerializer,
)
from cloudsneeker_api.serializers_ingestions import FindingIngestionSerializer
from cloudsneeker_api.serializers_scan_config import (
    ScanConfigurationSerializer,
    ScanConfigurationWriteSerializer,
)
from cloudsneeker_api.services.alert_conditions import preview_condition
from cloudsneeker_api.services.custodian import CustodianDryRunError, enqueue_custodian_dry_run
from cloudsneeker_api.services.custodian_schedule import (
    CustodianScheduleError,
    apply_schedule_to_policies,
    delete_policy_schedule,
)
from cloudsneeker_api.services.ocsf_import import parse_ocsf_payload
from django.db import transaction
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


class CustodianPolicyFilter(filters.FilterSet):
    class Meta:
        model = CustodianPolicy
        fields = {
            "name": ["exact", "icontains"],
            "provider": ["exact"],
        }


class CustodianRunFilter(filters.FilterSet):
    status = filters.CharFilter()
    policy = filters.UUIDFilter(field_name="policy_id")

    class Meta:
        model = CustodianRun
        fields = ["status", "policy"]


@extend_schema_view(
    list=extend_schema(tags=["Custodian"], summary="List Custodian policies"),
    retrieve=extend_schema(tags=["Custodian"], summary="Get a Custodian policy"),
    create=extend_schema(tags=["Custodian"], summary="Create a Custodian policy"),
    partial_update=extend_schema(tags=["Custodian"], summary="Update a Custodian policy"),
    destroy=extend_schema(tags=["Custodian"], summary="Delete a Custodian policy"),
)
class CustodianPolicyViewSet(BaseRLSViewSet):
    """CRUD for Cloud Custodian policies plus dry-run enqueue."""

    queryset = CustodianPolicy.objects.all()
    serializer_class = CustodianPolicySerializer
    filterset_class = CustodianPolicyFilter
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    search_fields = ["name", "description"]
    ordering = ["-inserted_at"]
    ordering_fields = ["name", "inserted_at", "updated_at"]
    required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        return (
            CustodianPolicy.objects.filter(tenant_id=self.request.tenant_id)
            .select_related("provider")
            .all()
        )

    def get_serializer_class(self):
        if self.action in ("create", "partial_update"):
            return CustodianPolicyWriteSerializer
        return CustodianPolicySerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        policy = serializer.save()
        policy = (
            CustodianPolicy.objects.select_related("provider").get(pk=policy.pk)
        )
        return Response(
            CustodianPolicySerializer(policy, context=self.get_serializer_context()).data,
            status=status.HTTP_201_CREATED,
        )

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        policy = serializer.save()
        policy = (
            CustodianPolicy.objects.select_related("provider").get(pk=policy.pk)
        )
        return Response(
            CustodianPolicySerializer(policy, context=self.get_serializer_context()).data
        )

    def perform_destroy(self, instance):
        policy_id = str(instance.id)
        super().perform_destroy(instance)
        delete_policy_schedule(policy_id)

    @action(
        detail=True,
        methods=["post"],
        url_path="dry-run",
        parser_classes=[LenientJSONAPIParser, JSONParser],
    )
    def dry_run(self, request, pk=None):
        """Enqueue a dry-run for this policy; never applies mutations."""
        policy = self.get_object()
        try:
            run = enqueue_custodian_dry_run(
                tenant_id=str(request.tenant_id),
                policy_id=str(policy.id),
            )
        except CustodianDryRunError as exc:
            return Response(
                {"errors": [{"detail": str(exc)}]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        run = CustodianRun.objects.select_related("policy", "provider").get(pk=run.pk)
        return Response(
            CustodianRunSerializer(run, context=self.get_serializer_context()).data,
            status=status.HTTP_202_ACCEPTED,
        )

    @action(
        detail=False,
        methods=["post"],
        url_path="schedule-bulk",
        parser_classes=[LenientJSONAPIParser, JSONParser],
    )
    def schedule_bulk(self, request):
        """Apply one schedule to many policies (by id list or provider)."""
        payload = request.data
        if isinstance(payload, dict) and "data" in payload:
            attributes = payload.get("data", {}).get("attributes", payload)
        else:
            attributes = payload
        serializer = CustodianScheduleBulkSerializer(data=attributes)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            policies = apply_schedule_to_policies(
                tenant_id=str(request.tenant_id),
                schedule_enabled=data["schedule_enabled"],
                schedule_cron=data.get("schedule_cron", ""),
                schedule_timezone=data.get("schedule_timezone", "UTC"),
                policy_ids=(
                    [str(pid) for pid in data["policy_ids"]]
                    if data.get("policy_ids")
                    else None
                ),
                provider_id=(
                    str(data["provider_id"]) if data.get("provider_id") else None
                ),
            )
        except CustodianScheduleError as exc:
            return Response(
                {"errors": [{"detail": str(exc)}]},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(
            CustodianPolicySerializer(
                policies, many=True, context=self.get_serializer_context()
            ).data,
            status=status.HTTP_200_OK,
        )


@extend_schema_view(
    list=extend_schema(tags=["Custodian"], summary="List Custodian dry-runs"),
    retrieve=extend_schema(tags=["Custodian"], summary="Get a Custodian dry-run"),
)
class CustodianRunViewSet(BaseRLSViewSet):
    """Read-only Custodian dry-run history."""

    queryset = CustodianRun.objects.all()
    serializer_class = CustodianRunSerializer
    filterset_class = CustodianRunFilter
    http_method_names = ["get", "head", "options"]
    ordering = ["-inserted_at"]
    ordering_fields = ["inserted_at", "status", "finished_at"]
    required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        return (
            CustodianRun.objects.filter(tenant_id=self.request.tenant_id)
            .select_related("policy", "provider")
            .all()
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

    @action(
        detail=False,
        methods=["post"],
        url_path="seed",
        parser_classes=[LenientJSONAPIParser, JSONParser, FormParser],
    )
    def seed(self, request, *args, **kwargs):
        # Hand-built envelope; disable JSON:API re-wrapping.
        self.resource_name = False
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

    @action(
        detail=False,
        methods=["post"],
        url_path="preview",
        parser_classes=[LenientJSONAPIParser, JSONParser, FormParser],
    )
    def preview(self, request, *args, **kwargs):
        # Hand-built envelope; disable JSON:API re-wrapping.
        self.resource_name = False
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
        from cloudsneeker_api.services.slack import (
            get_tenant_slack_integration,
            public_configuration,
        )

        integration = (
            get_tenant_slack_integration(str(tenant_id)) if tenant_id else None
        )
        if integration is None:
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

        configuration = public_configuration(integration.configuration or {})
        return Response(
            {
                "data": {
                    "type": "alert-slack-channels",
                    "id": str(tenant_id or "unknown"),
                    "attributes": {
                        "connected": integration.connected,
                        "workspace_name": configuration.get("team_name"),
                        "channels": [
                            {
                                "id": channel["id"],
                                "name": channel["name"],
                                "is_private": channel["is_private"],
                            }
                            for channel in configuration.get("channels") or []
                        ],
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
    serializer_class = FindingIngestionSerializer
    http_method_names = ["get", "post", "head", "options"]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    required_permissions = [Permissions.MANAGE_SCANS]
    # Documents are built by hand; skip JSON:API re-wrapping that would nest
    # another ``data`` key (and turn list pagination into ``data.results``).
    resource_name = False

    def get_queryset(self):
        return FindingIngestion.objects.filter(tenant_id=self.request.tenant_id)

    def _document(self, ingestion: FindingIngestion) -> dict:
        return {
            "type": "ingestions",
            "id": str(ingestion.id),
            "attributes": {
                "status": ingestion.status,
                "original_filename": ingestion.original_filename,
                "error_message": ingestion.error_message,
                "scan_id": str(ingestion.scan_id) if ingestion.scan_id else None,
                "summary": {
                    "total": ingestion.total_records,
                    "processed": ingestion.processed_records,
                    "invalid": ingestion.invalid_records,
                },
            },
        }

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        items = page if page is not None else list(queryset)
        documents = [self._document(item) for item in items]
        payload: dict = {"data": documents}
        if page is not None and self.paginator is not None:
            paginated = self.paginator.get_paginated_response(documents)
            payload["links"] = paginated.data.get("links")
            payload["meta"] = paginated.data.get("meta")
        return Response(payload)

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

        tenant_id = str(request.tenant_id)
        ingestion_id = str(ingestion.id)
        # Defer broker publish until the request atomic block commits so the
        # worker cannot race ahead of the FindingIngestion insert.
        transaction.on_commit(
            lambda: process_finding_ingestion_task.delay(
                tenant_id=tenant_id,
                ingestion_id=ingestion_id,
            )
        )
        return Response(
            {"data": self._document(ingestion)},
            status=status.HTTP_202_ACCEPTED,
        )
