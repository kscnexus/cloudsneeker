"""JSON:API serializers for per-tenant SMTP email delivery."""

from api.v1.serializers import BaseWriteSerializer, RLSSerializer
from cloudsneeker_api.models import EmailDeliveryConfig
from rest_framework import serializers
from rest_framework.exceptions import ValidationError


class EmailDeliveryConfigSerializer(RLSSerializer):
    """Read serializer; password is never exposed."""

    has_password = serializers.SerializerMethodField()

    class Meta:
        model = EmailDeliveryConfig
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "enabled",
            "host",
            "port",
            "use_tls",
            "use_ssl",
            "username",
            "from_email",
            "has_password",
        ]

    def get_has_password(self, obj) -> bool:
        return bool(obj._password)


class EmailDeliveryConfigWriteSerializer(RLSSerializer, BaseWriteSerializer):
    """Create/update SMTP settings; blank password keeps the stored value."""

    password = serializers.CharField(
        write_only=True, required=False, allow_blank=True, default=""
    )

    class Meta:
        model = EmailDeliveryConfig
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "enabled",
            "host",
            "port",
            "use_tls",
            "use_ssl",
            "username",
            "password",
            "from_email",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "enabled": {"required": False},
            "port": {"required": False},
            "use_tls": {"required": False},
            "use_ssl": {"required": False},
            "username": {"required": False},
        }

    def validate(self, attrs):
        use_tls = attrs.get(
            "use_tls", getattr(self.instance, "use_tls", True) if self.instance else True
        )
        use_ssl = attrs.get(
            "use_ssl", getattr(self.instance, "use_ssl", False) if self.instance else False
        )
        if use_tls and use_ssl:
            raise ValidationError(
                {"use_tls": "Cannot enable both TLS and SSL at the same time."}
            )
        port = attrs.get(
            "port", getattr(self.instance, "port", 587) if self.instance else 587
        )
        if port < 1 or port > 65535:
            raise ValidationError({"port": "Port must be between 1 and 65535."})
        return super().validate(attrs)

    def create(self, validated_data):
        password = validated_data.pop("password", "")
        config = super().create(validated_data)
        if password:
            config.password = password
            config.save(update_fields=["_password", "updated_at"])
        return config

    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        config = super().update(instance, validated_data)
        if password is not None and password != "":
            config.password = password
            config.save(update_fields=["_password", "updated_at"])
        return config
