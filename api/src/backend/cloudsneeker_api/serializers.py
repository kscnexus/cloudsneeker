from cloudsneeker_api.models import JSON_API_TYPE_PREFIX
from drf_spectacular.utils import extend_schema_serializer
from rest_framework import serializers


@extend_schema_serializer(component_name="Brand")
class BrandSerializer(serializers.Serializer):
    """Read-only description of the product brand (``cloudsneeker-brand``)."""

    name = serializers.CharField(read_only=True)
    short_name = serializers.CharField(read_only=True)
    vendor = serializers.CharField(read_only=True)
    tagline = serializers.CharField(read_only=True)
    website_url = serializers.URLField(read_only=True)
    docs_url = serializers.URLField(read_only=True)
    support_url = serializers.URLField(read_only=True)
    status_url = serializers.URLField(read_only=True)
    terms_url = serializers.URLField(read_only=True)
    privacy_url = serializers.URLField(read_only=True)
    logo_url = serializers.URLField(read_only=True)

    class Meta:
        resource_name = f"{JSON_API_TYPE_PREFIX}brand"
