"""JSON:API serializers for per-tenant Slack app credentials."""

from api.v1.serializers import BaseWriteSerializer, RLSSerializer
from cloudsneeker_api.models import SlackAppConfig
from rest_framework import serializers


class SlackAppConfigSerializer(RLSSerializer):
    """Read serializer; client secret is never exposed."""

    has_client_secret = serializers.SerializerMethodField()

    class Meta:
        model = SlackAppConfig
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "enabled",
            "client_id",
            "has_client_secret",
        ]

    def get_has_client_secret(self, obj) -> bool:
        return bool(obj._client_secret)


class SlackAppConfigWriteSerializer(RLSSerializer, BaseWriteSerializer):
    """Create/update Slack app credentials; blank secret keeps the stored value."""

    client_secret = serializers.CharField(
        write_only=True, required=False, allow_blank=True, default=""
    )

    class Meta:
        model = SlackAppConfig
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "enabled",
            "client_id",
            "client_secret",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "enabled": {"required": False},
        }

    def create(self, validated_data):
        client_secret = validated_data.pop("client_secret", "")
        config = super().create(validated_data)
        if client_secret:
            config.client_secret = client_secret
            config.save(update_fields=["_client_secret", "updated_at"])
        return config

    def update(self, instance, validated_data):
        client_secret = validated_data.pop("client_secret", None)
        config = super().update(instance, validated_data)
        if client_secret is not None and client_secret != "":
            config.client_secret = client_secret
            config.save(update_fields=["_client_secret", "updated_at"])
        return config
