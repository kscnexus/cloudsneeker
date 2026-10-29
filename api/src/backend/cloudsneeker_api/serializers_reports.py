"""JSON:API serializers for report runs, schedules, and share links."""

from __future__ import annotations

from api.v1.serializers import BaseSerializerV1, BaseWriteSerializer, RLSSerializer
from cloudsneeker_api.models import (
    JSON_API_TYPE_PREFIX,
    ReportRun,
    ReportSchedule,
    ReportShareLink,
)
from cloudsneeker_api.reports.catalog import (
    ReportParamsError,
    get_report_type,
    validate_formats,
    validate_params,
)
from cloudsneeker_api.reports.share import MAX_TTL_HOURS, link_state
from cloudsneeker_api.services.custodian_schedule import (
    CustodianScheduleError,
    parse_cron_fields,
    validate_timezone,
)
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

MAX_RECIPIENTS = 50


class ReportTypeSerializer(BaseSerializerV1):
    """Schema of a report catalog entry (documents are built by the view)."""

    name = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    audience = serializers.CharField(read_only=True)
    category = serializers.CharField(read_only=True)
    formats = serializers.ListField(child=serializers.CharField(), read_only=True)
    parameters = serializers.DictField(read_only=True)

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}report-types"


class ReportRunSerializer(RLSSerializer):
    """Read serializer for report runs."""

    report_name = serializers.SerializerMethodField()
    created_by_id = serializers.UUIDField(read_only=True, allow_null=True)
    schedule_id = serializers.UUIDField(read_only=True, allow_null=True)
    available_formats = serializers.SerializerMethodField()

    class Meta:
        model = ReportRun
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "report_type",
            "report_name",
            "params",
            "formats",
            "available_formats",
            "status",
            "trigger",
            "error",
            "started_at",
            "finished_at",
            "artifact_sizes",
            "size_bytes",
            "summary",
            "schedule_id",
            "created_by_id",
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}report-runs"

    def get_report_name(self, obj: ReportRun) -> str:
        try:
            return get_report_type(obj.report_type).name
        except ReportParamsError:
            return obj.report_type

    def get_available_formats(self, obj: ReportRun) -> list[str]:
        return sorted((obj.artifacts or {}).keys())


class ReportRunCreateSerializer(RLSSerializer, BaseWriteSerializer):
    """Validate a report run request; the view enqueues it."""

    params = serializers.JSONField(required=False)
    formats = serializers.JSONField(required=False)

    class Meta:
        model = ReportRun
        fields = ["id", "report_type", "params", "formats"]
        extra_kwargs = {"id": {"read_only": True}}

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}report-runs"

    def validate_report_type(self, value):
        try:
            get_report_type(value)
        except ReportParamsError as exc:
            raise ValidationError(str(exc)) from exc
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        report_type = attrs.get("report_type")
        try:
            attrs["params"] = validate_params(report_type, attrs.get("params") or {})
            attrs["formats"] = validate_formats(attrs.get("formats"))
        except ReportParamsError as exc:
            raise ValidationError({"params": str(exc)}) from exc
        return attrs


def _validate_recipients(value) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise ValidationError("recipients must be a list of email addresses.")
    field = serializers.EmailField()
    cleaned: list[str] = []
    for item in value:
        email = field.run_validation(item).strip().lower()
        if email not in cleaned:
            cleaned.append(email)
    if len(cleaned) > MAX_RECIPIENTS:
        raise ValidationError(f"At most {MAX_RECIPIENTS} recipients are allowed.")
    return cleaned


class ReportScheduleSerializer(RLSSerializer):
    """Read serializer for report schedules."""

    last_run_id = serializers.UUIDField(read_only=True, allow_null=True)
    created_by_id = serializers.UUIDField(read_only=True, allow_null=True)

    class Meta:
        model = ReportSchedule
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "report_type",
            "params",
            "formats",
            "schedule_cron",
            "schedule_timezone",
            "recipients",
            "enabled",
            "next_run_at",
            "last_run_at",
            "last_run_id",
            "created_by_id",
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}report-schedules"


class ReportScheduleWriteSerializer(RLSSerializer, BaseWriteSerializer):
    """Create / update serializer; the view syncs the beat task."""

    params = serializers.JSONField(required=False)
    formats = serializers.JSONField(required=False)
    recipients = serializers.JSONField(required=False)

    class Meta:
        model = ReportSchedule
        fields = [
            "id",
            "name",
            "report_type",
            "params",
            "formats",
            "schedule_cron",
            "schedule_timezone",
            "recipients",
            "enabled",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "name": {"required": False},
            "report_type": {"required": False},
            "schedule_cron": {"required": False},
            "schedule_timezone": {"required": False},
            "enabled": {"required": False},
        }

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}report-schedules"

    def validate_name(self, value):
        queryset = ReportSchedule.objects.filter(
            tenant_id=self.context.get("tenant_id"), name=value
        )
        if self.instance is not None:
            queryset = queryset.exclude(pk=self.instance.pk)
        if queryset.exists():
            raise ValidationError("A report schedule with this name already exists.")
        return value

    def validate_schedule_cron(self, value):
        try:
            parse_cron_fields(value)
        except CustodianScheduleError as exc:
            raise ValidationError(str(exc)) from exc
        return value.strip()

    def validate_schedule_timezone(self, value):
        try:
            return validate_timezone(value)
        except CustodianScheduleError as exc:
            raise ValidationError(str(exc)) from exc

    def validate_recipients(self, value):
        return _validate_recipients(value)

    def validate_report_type(self, value):
        try:
            get_report_type(value)
        except ReportParamsError as exc:
            raise ValidationError(str(exc)) from exc
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        instance = self.instance
        if instance is None:
            for name in ("name", "report_type", "schedule_cron"):
                if not attrs.get(name):
                    raise ValidationError({name: "This field is required."})
        report_type = attrs.get("report_type") or (instance.report_type if instance else None)
        params = attrs.get("params")
        if params is None and instance is not None:
            params = instance.params
        try:
            attrs["params"] = validate_params(report_type, params or {})
            if "formats" in attrs or instance is None:
                attrs["formats"] = validate_formats(attrs.get("formats"))
        except ReportParamsError as exc:
            raise ValidationError({"params": str(exc)}) from exc
        return attrs


class ReportShareLinkSerializer(RLSSerializer):
    """Read serializer for share links (never exposes the token)."""

    report_run_id = serializers.UUIDField(read_only=True)
    state = serializers.SerializerMethodField()

    class Meta:
        model = ReportShareLink
        fields = [
            "id",
            "inserted_at",
            "report_run_id",
            "expires_at",
            "revoked_at",
            "last_accessed_at",
            "access_count",
            "state",
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}report-share-links"

    def get_state(self, obj: ReportShareLink) -> str:
        return link_state(obj)


class ReportShareLinkCreateSerializer(serializers.Serializer):
    """Validate a share link request."""

    expires_in_hours = serializers.IntegerField(
        required=False, min_value=1, max_value=MAX_TTL_HOURS
    )

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}report-share-links"
