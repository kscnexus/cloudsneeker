"""Container registry image / tag filters on the image provider secret."""

import pytest
from api.v1.serializers import ImageProviderSecret
from cloudsneeker_api.image_filters import validate_image_filter_patterns
from rest_framework import serializers


class TestValidateImageFilterPatterns:
    def test_keeps_valid_filters(self):
        attrs = {"image_filter": " ^prod/.* ", "tag_filter": r"^v\d+$"}

        validate_image_filter_patterns(attrs)

        assert attrs == {"image_filter": "^prod/.*", "tag_filter": r"^v\d+$"}

    def test_drops_blank_filters(self):
        attrs = {"image_filter": "  ", "tag_filter": ""}

        validate_image_filter_patterns(attrs)

        assert attrs == {}

    def test_rejects_invalid_regex(self):
        with pytest.raises(serializers.ValidationError):
            validate_image_filter_patterns({"image_filter": "(unclosed"})


class TestImageProviderSecretFilters:
    def test_filters_survive_validation(self):
        serializer = ImageProviderSecret(
            data={"image_filter": "^webgoat/.*", "tag_filter": "^latest$"}
        )

        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data["image_filter"] == "^webgoat/.*"
        assert serializer.validated_data["tag_filter"] == "^latest$"

    def test_invalid_filter_is_a_validation_error(self):
        serializer = ImageProviderSecret(data={"tag_filter": "[bad"})

        assert not serializer.is_valid()

    def test_credentials_rules_still_apply(self):
        serializer = ImageProviderSecret(data={"registry_username": "only-user"})

        assert not serializer.is_valid()
