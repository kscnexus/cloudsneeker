"""Validation for container registry image / tag filters."""

import re

from rest_framework import serializers

FILTER_FIELDS = ("image_filter", "tag_filter")


def validate_image_filter_patterns(attrs: dict) -> None:
    """Reject filters the scanner would fail on, and drop empty ones.

    The image provider compiles both values as regular expressions; a bad one
    would only surface as a failed scan.

    Args:
        attrs: Validated secret attributes, updated in place.

    Raises:
        serializers.ValidationError: A filter is not a valid regular expression.
    """
    for field in FILTER_FIELDS:
        value = attrs.get(field)
        if value is None:
            continue
        value = value.strip()
        if not value:
            attrs.pop(field)
            continue
        try:
            re.compile(value)
        except re.error as exc:
            raise serializers.ValidationError(
                {field: f"Invalid regular expression: {exc}"}
            ) from exc
        attrs[field] = value
