"""Parsers that accept Cloudsneeker JSON:API action envelopes."""

from rest_framework.parsers import JSONParser


class LenientJSONAPIParser(JSONParser):
    """Accept application/vnd.api+json without enforcing the viewset resource type.

    Seed and preview actions use distinct resource types
    (``alert-rule-seedings``, ``alert-rule-previews``) while living on the
    ``alert-rules`` collection. The stock JSON:API parser rejects those with
    HTTP 409 before the action runs.
    """

    media_type = "application/vnd.api+json"

    def parse(self, stream, media_type=None, parser_context=None):
        parsed = super().parse(stream, media_type=media_type, parser_context=parser_context)
        if not isinstance(parsed, dict):
            return parsed
        resource = parsed.get("data")
        if not isinstance(resource, dict):
            return parsed
        attributes = resource.get("attributes")
        if isinstance(attributes, dict):
            return attributes
        return parsed
