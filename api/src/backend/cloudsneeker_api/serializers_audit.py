"""JSON:API serializer for audit events (read-only)."""

from __future__ import annotations

from api.v1.serializers import RLSSerializer
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX, AuditEvent

AUDIT_EVENT_FIELDS = [
    "id",
    "inserted_at",
    "actor_id",
    "actor_email",
    "action",
    "target_type",
    "target_id",
    "target_label",
    "outcome",
    "status_code",
    "ip_address",
    "user_agent",
    "request_id",
    "method",
    "path",
    "metadata",
]


class AuditEventSerializer(RLSSerializer):
    """One recorded user action. Every field is read-only."""

    class Meta:
        model = AuditEvent
        fields = AUDIT_EVENT_FIELDS
        read_only_fields = AUDIT_EVENT_FIELDS

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}audit-events"
