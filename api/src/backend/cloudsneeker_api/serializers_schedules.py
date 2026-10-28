"""JSON:API serializers for provider scan schedules."""

from rest_framework import serializers


class ScheduleAttributesSerializer(serializers.Serializer):
    scan_enabled = serializers.BooleanField()
    scan_frequency = serializers.ChoiceField(
        choices=["DAILY", "WEEKLY", "MONTHLY", "INTERVAL"]
    )
    scan_hour = serializers.IntegerField(required=False, allow_null=True, min_value=0, max_value=23)
    scan_timezone = serializers.CharField(required=False, allow_blank=True, default="UTC")
    scan_interval_hours = serializers.IntegerField(
        required=False, allow_null=True, min_value=24
    )
    scan_day_of_week = serializers.IntegerField(
        required=False, allow_null=True, min_value=0, max_value=6
    )
    scan_day_of_month = serializers.IntegerField(
        required=False, allow_null=True, min_value=1, max_value=28
    )

    class JSONAPIMeta:
        resource_name = "schedules"


class ScheduleBulkSerializer(serializers.Serializer):
    schedule = ScheduleAttributesSerializer()
    provider_ids = serializers.ListField(
        child=serializers.UUIDField(), allow_empty=False
    )

    class JSONAPIMeta:
        resource_name = "schedules-bulk"
