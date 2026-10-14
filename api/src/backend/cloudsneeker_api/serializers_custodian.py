"""JSON:API serializers for Cloud Custodian policies and dry-runs."""

from api.models import Provider
from api.v1.serializers import BaseWriteSerializer, RLSSerializer
from cloudsneeker_api.models import CustodianPolicy, CustodianRun, JSON_API_TYPE_PREFIX
from cloudsneeker_api.services.custodian import (
    CustodianDryRunError,
    assert_policy_matches_provider,
    is_custodian_supported_provider,
)
from cloudsneeker_api.services.custodian_schedule import (
    CustodianScheduleError,
    parse_cron_fields,
    sync_policy_schedule,
    validate_timezone,
)
from rest_framework import serializers
from rest_framework.exceptions import ValidationError


class CustodianPolicySerializer(RLSSerializer):
    """Read serializer for Custodian policies."""

    provider_id = serializers.UUIDField(source="provider.id", read_only=True)
    provider_uid = serializers.CharField(source="provider.uid", read_only=True)
    provider_alias = serializers.CharField(
        source="provider.alias", read_only=True, allow_null=True
    )
    provider_type = serializers.CharField(source="provider.provider", read_only=True)

    class Meta:
        model = CustodianPolicy
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "description",
            "policy_yaml",
            "provider_id",
            "provider_uid",
            "provider_alias",
            "provider_type",
            "schedule_enabled",
            "schedule_cron",
            "schedule_timezone",
            "next_run_at",
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}custodian-policies"


class CustodianPolicyWriteSerializer(RLSSerializer, BaseWriteSerializer):
    """Create/update serializer for Custodian-supported cloud providers."""

    provider_id = serializers.UUIDField(write_only=True, required=False)

    class Meta:
        model = CustodianPolicy
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "description",
            "policy_yaml",
            "provider_id",
            "schedule_enabled",
            "schedule_cron",
            "schedule_timezone",
            "next_run_at",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "next_run_at": {"read_only": True},
            "name": {"required": False},
            "description": {"required": False},
            "policy_yaml": {"required": False},
            "schedule_enabled": {"required": False},
            "schedule_cron": {"required": False},
            "schedule_timezone": {"required": False},
        }

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}custodian-policies"

    def validate_name(self, value):
        tenant_id = self.context.get("tenant_id")
        queryset = CustodianPolicy.objects.filter(tenant_id=tenant_id, name=value)
        if self.instance:
            queryset = queryset.exclude(pk=self.instance.pk)
        if queryset.exists():
            raise ValidationError("A Custodian policy with this name already exists.")
        return value

    def validate_provider_id(self, value):
        tenant_id = self.context.get("tenant_id")
        provider = Provider.objects.filter(tenant_id=tenant_id, id=value).first()
        if provider is None:
            raise ValidationError("Unknown provider ID for this tenant.")
        if not is_custodian_supported_provider(provider.provider):
            raise ValidationError(
                "Cloud Custodian supports AWS, Azure, GCP, and Kubernetes providers only."
            )
        return value

    def validate_schedule_timezone(self, value):
        try:
            return validate_timezone(value)
        except CustodianScheduleError as exc:
            raise ValidationError(str(exc)) from exc

    def validate(self, attrs):
        attrs = super().validate(attrs)
        provider_id = attrs.get("provider_id")
        policy_yaml = attrs.get("policy_yaml")
        if provider_id is None and self.instance is not None:
            provider_type = self.instance.provider.provider
        elif provider_id is not None:
            tenant_id = self.context.get("tenant_id")
            provider = Provider.objects.filter(
                tenant_id=tenant_id, id=provider_id
            ).first()
            if provider is None:
                raise ValidationError(
                    {"provider_id": "Unknown provider ID for this tenant."}
                )
            provider_type = provider.provider
        else:
            provider_type = None

        if policy_yaml is None and self.instance is not None:
            policy_yaml = self.instance.policy_yaml
        if policy_yaml is not None and provider_type is not None:
            try:
                assert_policy_matches_provider(policy_yaml, provider_type)
            except CustodianDryRunError as exc:
                raise ValidationError({"policy_yaml": str(exc)}) from exc

        schedule_enabled = attrs.get(
            "schedule_enabled",
            self.instance.schedule_enabled if self.instance else False,
        )
        schedule_cron = attrs.get(
            "schedule_cron",
            self.instance.schedule_cron if self.instance else "",
        )
        if schedule_enabled:
            try:
                parse_cron_fields(schedule_cron)
            except CustodianScheduleError as exc:
                raise ValidationError({"schedule_cron": str(exc)}) from exc
        return attrs

    def create(self, validated_data):
        provider_id = validated_data.pop("provider_id", None)
        if provider_id is None:
            raise ValidationError({"provider_id": "This field is required."})
        if "name" not in validated_data:
            raise ValidationError({"name": "This field is required."})
        if "policy_yaml" not in validated_data:
            raise ValidationError({"policy_yaml": "This field is required."})
        validated_data["provider_id"] = provider_id
        policy = super().create(validated_data)
        return sync_policy_schedule(policy)

    def update(self, instance, validated_data):
        provider_id = validated_data.pop("provider_id", None)
        if provider_id is not None:
            validated_data["provider_id"] = provider_id
        policy = super().update(instance, validated_data)
        return sync_policy_schedule(policy)


class CustodianScheduleBulkSerializer(serializers.Serializer):
    """Apply one schedule to many policies by id or provider."""

    policy_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        allow_empty=False,
    )
    provider_id = serializers.UUIDField(required=False)
    schedule_enabled = serializers.BooleanField()
    schedule_cron = serializers.CharField(required=False, allow_blank=True, default="")
    schedule_timezone = serializers.CharField(required=False, default="UTC")

    def validate(self, attrs):
        if not attrs.get("policy_ids") and not attrs.get("provider_id"):
            raise ValidationError("Provide policy_ids or provider_id.")
        if attrs.get("schedule_enabled"):
            try:
                parse_cron_fields(attrs.get("schedule_cron", ""))
                attrs["schedule_timezone"] = validate_timezone(
                    attrs.get("schedule_timezone", "UTC")
                )
            except CustodianScheduleError as exc:
                raise ValidationError({"schedule_cron": str(exc)}) from exc
        return attrs


class CustodianRunSerializer(RLSSerializer):
    """Read serializer for Custodian dry-run jobs."""

    class Meta:
        model = CustodianRun
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "policy_id",
            "provider_id",
            "status",
            "mode",
            "trigger",
            "started_at",
            "finished_at",
            "summary",
            "output",
            "error",
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}custodian-runs"

