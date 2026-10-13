"""JSON:API envelopes for Cloudsneeker configuration features."""

from io import BytesIO

from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.views_features import AlertRuleViewSet, IngestionViewSet
from rest_framework.parsers import JSONParser


class TestLenientJSONAPIParser:
    def test_unwraps_alert_rule_seedings_attributes(self):
        body = (
            b'{"data":{"type":"alert-rule-seedings","attributes":'
            b'{"filter_bag":{"severity":["high"]}}}}'
        )
        parser = LenientJSONAPIParser()
        result = parser.parse(BytesIO(body), media_type=parser.media_type)

        assert result == {"filter_bag": {"severity": ["high"]}}

    def test_unwraps_alert_rule_previews_attributes(self):
        body = (
            b'{"data":{"type":"alert-rule-previews","attributes":'
            b'{"condition":{"op":"count_gte","value":1}}}}'
        )
        parser = LenientJSONAPIParser()
        result = parser.parse(BytesIO(body), media_type=parser.media_type)

        assert result == {"condition": {"op": "count_gte", "value": 1}}

    def test_passes_through_non_envelope_json(self):
        body = b'{"filter_bag":{"severity":["critical"]}}'
        parser = LenientJSONAPIParser()
        result = parser.parse(BytesIO(body), media_type=parser.media_type)

        assert result == {"filter_bag": {"severity": ["critical"]}}


class TestIngestionDocumentEnvelope:
    def test_document_is_a_jsonapi_resource_object(self):
        class _Ingestion:
            id = "11111111-1111-1111-1111-111111111111"
            status = "completed"
            original_filename = "findings.json"
            error_message = ""
            scan_id = "01hxyz"
            total_records = 3
            processed_records = 2
            invalid_records = 1

        document = IngestionViewSet()._document(_Ingestion())

        assert document == {
            "type": "ingestions",
            "id": "11111111-1111-1111-1111-111111111111",
            "attributes": {
                "status": "completed",
                "original_filename": "findings.json",
                "error_message": "",
                "scan_id": "01hxyz",
                "summary": {"total": 3, "processed": 2, "invalid": 1},
            },
        }

    def test_viewset_disables_jsonapi_resource_wrapping(self):
        # Hand-built documents must pass through the renderer unchanged.
        assert IngestionViewSet.resource_name is False


class TestSeedPreviewParserWiring:
    def test_seed_accepts_lenient_jsonapi(self):
        parsers = AlertRuleViewSet.seed.kwargs["parser_classes"]
        assert LenientJSONAPIParser in parsers
        assert JSONParser in parsers

    def test_preview_accepts_lenient_jsonapi(self):
        parsers = AlertRuleViewSet.preview.kwargs["parser_classes"]
        assert LenientJSONAPIParser in parsers
        assert JSONParser in parsers
