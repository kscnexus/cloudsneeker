"""JSON:API serializers for alert rules and recipients."""

import secrets
from datetime import timedelta

from api.v1.serializers import BaseWriteSerializer, RLSSerializer
from cloudsneeker_api.models import (
    AlertEvent,
    AlertRecipient,
    AlertRule,
    AlertRuleRecipient,
)
from cloudsneeker_api.services.alert_events import NOTE_MAX_LENGTH, set_status
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

ALERT_TRIGGER_VALUES = {choice.value for choice in AlertRule.Trigger}


class AlertRecipientSerializer(RLSSerializer):
    """Read serializer for alert recipients."""

    class Meta:
        model = AlertRecipient
        fields = [
            "id",
            "email",
            "status",
            "confirmation_sent_at",
            "confirmation_expires_at",
            "confirmed_at",
            "unsubscribed_at",
            "last_bounce_at",
            "inserted_at",
            "updated_at",
        ]


class AlertRuleSerializer(RLSSerializer):
    """Read serializer for alert rules."""

    recipient_emails = serializers.SerializerMethodField()
    slack_channels = serializers.SerializerMethodField()
    created_by = serializers.SerializerMethodField()

    class Meta:
        model = AlertRule
        fields = [
            "id",
            "name",
            "description",
            "enabled",
            "trigger",
            "condition",
            "schema_version",
            "recipient_emails",
            "slack_channels",
            "created_by",
            "inserted_at",
            "updated_at",
        ]

    def get_recipient_emails(self, obj):
        return list(obj.recipients.values_list("email", flat=True))

    def get_slack_channels(self, obj):
        # Cloudsneeker keeps Slack channel ids; names resolve when Slack is connected.
        return [{"id": channel_id} for channel_id in (obj.slack_channel_ids or [])]

    def get_created_by(self, obj):
        if not obj.created_by_id:
            return None
        return str(obj.created_by_id)


class AlertRuleWriteSerializer(RLSSerializer, BaseWriteSerializer):
    """Create/update serializer for alert rules."""

    recipient_emails = serializers.ListField(
        child=serializers.EmailField(),
        required=False,
        write_only=True,
    )
    slack_channels = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        write_only=True,
    )
    condition = serializers.JSONField(required=False)
    trigger = serializers.ChoiceField(
        choices=AlertRule.Trigger.choices, required=False
    )
    schema_version = serializers.IntegerField(required=False)

    class Meta:
        model = AlertRule
        fields = [
            "id",
            "name",
            "description",
            "enabled",
            "trigger",
            "condition",
            "schema_version",
            "recipient_emails",
            "slack_channels",
            "inserted_at",
            "updated_at",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "name": {"required": False},
            "description": {"required": False},
            "enabled": {"required": False},
        }

    def validate_name(self, value):
        tenant_id = self.context.get("tenant_id")
        queryset = AlertRule.objects.filter(tenant_id=tenant_id, name=value)
        if self.instance:
            queryset = queryset.exclude(pk=self.instance.pk)
        if queryset.exists():
            raise ValidationError("An alert rule with this name already exists.")
        return value

    def validate_condition(self, value):
        if not isinstance(value, dict) or "op" not in value:
            raise ValidationError("Condition must be an object with an op field.")
        return value

    def validate_slack_channels(self, value):
        channel_ids = []
        for item in value:
            channel_id = item.get("id") if isinstance(item, dict) else None
            if not channel_id or not isinstance(channel_id, str):
                raise ValidationError("Each Slack channel must include an id.")
            channel_ids.append(channel_id)
        return channel_ids

    def create(self, validated_data):
        recipient_emails = validated_data.pop("recipient_emails", [])
        slack_channel_ids = validated_data.pop("slack_channels", [])
        if "name" not in validated_data:
            raise ValidationError({"name": "This field is required."})
        if "trigger" not in validated_data:
            raise ValidationError({"trigger": "This field is required."})
        if "condition" not in validated_data:
            raise ValidationError({"condition": "This field is required."})
        validated_data["slack_channel_ids"] = slack_channel_ids
        request = self.context.get("request")
        if request and getattr(request, "user", None):
            validated_data["created_by"] = request.user
        rule = super().create(validated_data)
        self._replace_recipients(rule, recipient_emails)
        return rule

    def update(self, instance, validated_data):
        recipient_emails = validated_data.pop("recipient_emails", None)
        slack_channel_ids = validated_data.pop("slack_channels", None)
        if slack_channel_ids is not None:
            validated_data["slack_channel_ids"] = slack_channel_ids
        rule = super().update(instance, validated_data)
        if recipient_emails is not None:
            self._replace_recipients(rule, recipient_emails)
        return rule

    def _replace_recipients(self, rule: AlertRule, emails: list[str]):
        tenant_id = self.context.get("tenant_id")
        recipients = []
        now = timezone.now()
        for email in emails:
            recipient, created = AlertRecipient.objects.get_or_create(
                tenant_id=tenant_id,
                email=email.lower(),
                defaults={
                    "status": AlertRecipient.Status.CONFIRMED,
                    "confirmation_token": secrets.token_urlsafe(24),
                    "unsubscribe_token": secrets.token_urlsafe(24),
                    "confirmed_at": now,
                    "confirmation_sent_at": now,
                    "confirmation_expires_at": now + timedelta(days=7),
                },
            )
            if created is False and not recipient.unsubscribe_token:
                recipient.unsubscribe_token = secrets.token_urlsafe(24)
                recipient.save(update_fields=["unsubscribe_token", "updated_at"])
            recipients.append(recipient)

        rule.recipient_links.all().delete()
        AlertRuleRecipient.objects.bulk_create(
            [
                AlertRuleRecipient(
                    tenant_id=tenant_id,
                    rule=rule,
                    recipient=recipient,
                )
                for recipient in recipients
            ]
        )


class AlertEventSerializer(RLSSerializer):
    """Read serializer for alert history."""

    rule_id = serializers.SerializerMethodField()
    status_changed_by = serializers.SerializerMethodField()

    class Meta:
        model = AlertEvent
        fields = [
            "id",
            "rule_id",
            "rule_name",
            "trigger",
            "scan_id",
            "custodian_run_id",
            "areas",
            "area_counts",
            "severity_counts",
            "total",
            "links",
            "delivered",
            "status",
            "status_changed_at",
            "status_changed_by",
            "note",
            "inserted_at",
            "updated_at",
        ]

    def get_rule_id(self, obj):
        return str(obj.rule_id) if obj.rule_id else None

    def get_status_changed_by(self, obj):
        user = obj.status_changed_by
        if user is None:
            return None
        return {"id": str(user.id), "name": user.name or user.email}


class AlertEventUpdateSerializer(BaseWriteSerializer):
    """Status and note of an alert event; nothing else is writable."""

    status = serializers.ChoiceField(
        choices=AlertEvent.Status.choices, required=False
    )
    note = serializers.CharField(
        max_length=NOTE_MAX_LENGTH, required=False, allow_blank=True
    )

    class Meta:
        model = AlertEvent
        fields = ["status", "note"]

    def update(self, instance, validated_data):
        return set_status(
            instance,
            status=validated_data.get("status", instance.status),
            user=self.context["request"].user,
            note=validated_data.get("note"),
        )
