"""JSON:API serializers for scan configurations."""

from api.models import Provider
from api.v1.serializers import BaseWriteSerializer, RLSSerializer
from cloudsneeker_api.models import ScanConfiguration, ScanConfigurationProvider
from rest_framework import serializers
from rest_framework.exceptions import ValidationError


class ScanConfigurationSerializer(RLSSerializer):
    """Read serializer for scan configurations."""

    providers = serializers.SerializerMethodField()
    configuration = serializers.JSONField()

    class Meta:
        model = ScanConfiguration
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "configuration",
            "providers",
        ]

    def get_providers(self, obj):
        return [
            str(provider_id)
            for provider_id in obj.providers.values_list("id", flat=True)
        ]


class ScanConfigurationWriteSerializer(RLSSerializer, BaseWriteSerializer):
    """Create/update serializer; accepts provider_ids and configuration mapping."""

    provider_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        write_only=True,
    )
    configuration = serializers.JSONField(required=False)

    class Meta:
        model = ScanConfiguration
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "configuration",
            "provider_ids",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "name": {"required": False},
            "configuration": {"required": False},
        }

    def validate_name(self, value):
        tenant_id = self.context.get("tenant_id")
        queryset = ScanConfiguration.objects.filter(tenant_id=tenant_id, name=value)
        if self.instance:
            queryset = queryset.exclude(pk=self.instance.pk)
        if queryset.exists():
            raise ValidationError("A scan configuration with this name already exists.")
        return value

    def validate_configuration(self, value):
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValidationError("Configuration must be a mapping with provider sections.")
        return value

    def validate_provider_ids(self, value):
        tenant_id = self.context.get("tenant_id")
        if not value:
            return []
        found = set(
            Provider.objects.filter(tenant_id=tenant_id, id__in=value).values_list(
                "id", flat=True
            )
        )
        missing = set(value) - found
        if missing:
            raise ValidationError(
                f"Unknown provider IDs for this tenant: {sorted(str(item) for item in missing)}"
            )
        return list(value)

    def create(self, validated_data):
        provider_ids = validated_data.pop("provider_ids", [])
        if "name" not in validated_data:
            raise ValidationError({"name": "This field is required."})
        if "configuration" not in validated_data:
            raise ValidationError({"configuration": "This field is required."})
        config = super().create(validated_data)
        self._replace_providers(config, provider_ids)
        return config

    def update(self, instance, validated_data):
        provider_ids = validated_data.pop("provider_ids", None)
        config = super().update(instance, validated_data)
        if provider_ids is not None:
            self._replace_providers(config, provider_ids)
        return config

    def _replace_providers(self, config: ScanConfiguration, provider_ids: list):
        tenant_id = self.context.get("tenant_id")
        # A provider may belong to only one configuration in this tenant.
        ScanConfigurationProvider.objects.filter(
            tenant_id=tenant_id, provider_id__in=provider_ids
        ).exclude(scan_configuration=config).delete()
        config.provider_links.all().delete()
        ScanConfigurationProvider.objects.bulk_create(
            [
                ScanConfigurationProvider(
                    tenant_id=tenant_id,
                    scan_configuration=config,
                    provider_id=provider_id,
                )
                for provider_id in provider_ids
            ]
        )
