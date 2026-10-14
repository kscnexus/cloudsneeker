"""JSON:API serializers for Cloud Custodian policies and dry-runs."""

from api.models import Provider
from api.v1.serializers import BaseWriteSerializer, RLSSerializer
from cloudsneeker_api.models import CustodianPolicy, CustodianRun, JSON_API_TYPE_PREFIX
from cloudsneeker_api.services.custodian import CustodianDryRunError, parse_policy_yaml
from rest_framework import serializers
from rest_framework.exceptions import ValidationError


class CustodianPolicySerializer(RLSSerializer):
    """Read serializer for Custodian policies."""

    provider_id = serializers.UUIDField(source="provider.id", read_only=True)
    provider_uid = serializers.CharField(source="provider.uid", read_only=True)
    provider_alias = serializers.CharField(
        source="provider.alias", read_only=True, allow_null=True
    )

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
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}custodian-policies"


class CustodianPolicyWriteSerializer(RLSSerializer, BaseWriteSerializer):
    """Create/update serializer; AWS providers only."""

    provider_id = serializers.UUIDField(write_only=True)

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
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "name": {"required": False},
            "description": {"required": False},
            "policy_yaml": {"required": False},
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

    def validate_policy_yaml(self, value):
        try:
            parse_policy_yaml(value)
        except CustodianDryRunError as exc:
            raise ValidationError(str(exc)) from exc
        return value

    def validate_provider_id(self, value):
        tenant_id = self.context.get("tenant_id")
        provider = Provider.objects.filter(tenant_id=tenant_id, id=value).first()
        if provider is None:
            raise ValidationError("Unknown provider ID for this tenant.")
        if provider.provider != Provider.ProviderChoices.AWS.value:
            raise ValidationError("Cloud Custodian dry-run supports AWS providers only.")
        return value

    def create(self, validated_data):
        provider_id = validated_data.pop("provider_id")
        if "name" not in validated_data:
            raise ValidationError({"name": "This field is required."})
        if "policy_yaml" not in validated_data:
            raise ValidationError({"policy_yaml": "This field is required."})
        validated_data["provider_id"] = provider_id
        return super().create(validated_data)

    def update(self, instance, validated_data):
        provider_id = validated_data.pop("provider_id", None)
        if provider_id is not None:
            validated_data["provider_id"] = provider_id
        return super().update(instance, validated_data)


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
            "started_at",
            "finished_at",
            "summary",
            "output",
            "error",
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}custodian-runs"
