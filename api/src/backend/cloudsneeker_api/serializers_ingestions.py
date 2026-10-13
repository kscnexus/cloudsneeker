"""Serializers for CLI finding ingestions."""

from api.v1.serializers import RLSSerializer
from cloudsneeker_api.models import FindingIngestion


class FindingIngestionSerializer(RLSSerializer):
    """Read serializer for import job status."""

    class Meta:
        model = FindingIngestion
        fields = [
            "id",
            "status",
            "original_filename",
            "total_records",
            "processed_records",
            "invalid_records",
            "error_message",
            "scan_id",
            "inserted_at",
            "updated_at",
        ]
        read_only_fields = fields
