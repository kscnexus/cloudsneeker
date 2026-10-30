"""Request bodies of the operator console API and ``/entitlements``.

Responses are hand-built JSON:API documents (``views_operator``); these
serializers validate writes and describe them in the OpenAPI schema.
"""

from __future__ import annotations

from api.v1.serializers import BaseSerializerV1
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX
from cloudsneeker_api.services import plan_catalog as catalog
from rest_framework import serializers


class SubscriptionUpdateSerializer(BaseSerializerV1):
    """``PATCH /operator/subscriptions/{tenant_id}``. Every field is optional."""

    plan = serializers.CharField(required=False, help_text="Plan code.")
    status = serializers.ChoiceField(choices=catalog.STATUS_CHOICES, required=False)
    starts_at = serializers.DateTimeField(required=False, allow_null=True)
    ends_at = serializers.DateTimeField(required=False, allow_null=True)
    trial_ends_at = serializers.DateTimeField(required=False, allow_null=True)
    seats = serializers.IntegerField(required=False, allow_null=True, min_value=0)
    feature_overrides = serializers.DictField(
        child=serializers.BooleanField(), required=False
    )
    limit_overrides = serializers.DictField(
        child=serializers.IntegerField(allow_null=True, min_value=0), required=False
    )
    billing_source = serializers.ChoiceField(
        choices=catalog.BILLING_SOURCE_CHOICES, required=False
    )
    external_customer_id = serializers.CharField(
        required=False, allow_blank=True, max_length=255
    )
    notes = serializers.CharField(required=False, allow_blank=True)

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}subscriptions"


class PlanWriteSerializer(BaseSerializerV1):
    """``POST /operator/plans`` and ``PATCH /operator/plans/{code}``."""

    code = serializers.SlugField(max_length=50, required=False)
    name = serializers.CharField(max_length=100, required=False)
    description = serializers.CharField(required=False, allow_blank=True)
    features = serializers.ListField(
        child=serializers.ChoiceField(choices=list(catalog.FEATURE_KEYS)),
        required=False,
    )
    limits = serializers.DictField(
        child=serializers.IntegerField(allow_null=True, min_value=0), required=False
    )
    is_public = serializers.BooleanField(required=False)
    sort_order = serializers.IntegerField(required=False)

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}plans"

    def validate_limits(self, value):
        unknown = [key for key in value if key not in catalog.LIMIT_KEYS]
        if unknown:
            raise serializers.ValidationError(
                f"Unknown limit keys: {', '.join(sorted(unknown))}."
            )
        return catalog.clean_limits(value)

    def validate_features(self, value):
        return catalog.clean_features(value)
