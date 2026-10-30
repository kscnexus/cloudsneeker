"""JSON:API serializers for finding triage and its notes.

Attribute names follow the contract the inherited findings UI already reads
(``ui/actions/findings/findings-triage.adapter.ts``): ``status``,
``finding_uid``, ``finding_id``, ``raw_finding_status``,
``triage_notes_count``, ``has_note``, ``note_id`` and ``current_note``.
"""

from __future__ import annotations

from typing import Any

from api.v1.serializers import BaseSerializerV1, RLSSerializer
from cloudsneeker_api.models import (
    FINDING_TRIAGE_NOTE_MAX_LENGTH,
    JSON_API_TYPE_PREFIX,
    FindingTriage,
    FindingTriageNote,
)
from cloudsneeker_api.services.finding_triage import (
    BULK_MAX_FINDINGS,
    FindingSnapshot,
    effective_status,
)
from rest_framework import serializers

TRIAGE_RESOURCE = f"{JSON_API_TYPE_PREFIX}finding-triages"
NOTE_RESOURCE = f"{JSON_API_TYPE_PREFIX}finding-triage-notes"


class FindingTriageSerializer(RLSSerializer):
    """Read serializer; ``context["findings"]`` maps UID to ``FindingSnapshot``."""

    status = serializers.SerializerMethodField()
    stored_status = serializers.CharField(source="status", read_only=True)
    provider_id = serializers.UUIDField(read_only=True, allow_null=True)
    assignee_id = serializers.UUIDField(read_only=True, allow_null=True)
    updated_by_id = serializers.UUIDField(read_only=True, allow_null=True)
    finding_id = serializers.SerializerMethodField()
    raw_finding_status = serializers.SerializerMethodField()
    triage_notes_count = serializers.SerializerMethodField()
    has_note = serializers.SerializerMethodField()
    note_id = serializers.SerializerMethodField()
    current_note = serializers.SerializerMethodField()

    class Meta:
        model = FindingTriage
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "finding_uid",
            "finding_id",
            "status",
            "stored_status",
            "status_changed_at",
            "source",
            "check_id",
            "provider_id",
            "assignee_id",
            "updated_by_id",
            "raw_finding_status",
            "triage_notes_count",
            "has_note",
            "note_id",
            "current_note",
        ]

    class JSONAPIMeta:
        resource_name = TRIAGE_RESOURCE

    def _finding(self, obj: FindingTriage) -> FindingSnapshot | None:
        return (self.context.get("findings") or {}).get(obj.finding_uid)

    def get_status(self, obj: FindingTriage) -> str:
        return effective_status(obj, self._finding(obj))

    def get_finding_id(self, obj: FindingTriage) -> str | None:
        finding = self._finding(obj)
        return finding.id if finding else None

    def get_raw_finding_status(self, obj: FindingTriage) -> str | None:
        finding = self._finding(obj)
        return finding.status if finding else None

    def get_triage_notes_count(self, obj: FindingTriage) -> int:
        return int(getattr(obj, "notes_total", 0) or 0)

    def get_has_note(self, obj: FindingTriage) -> bool:
        return self.get_triage_notes_count(obj) > 0

    def get_note_id(self, obj: FindingTriage) -> str | None:
        note_id = getattr(obj, "latest_note_id", None)
        return str(note_id) if note_id else None

    def get_current_note(self, obj: FindingTriage) -> str:
        return getattr(obj, "latest_note_body", None) or ""


class FindingTriageUpdateSerializer(BaseSerializerV1):
    """PATCH body: any of status, note, assignee."""

    status = serializers.ChoiceField(
        choices=FindingTriage.Status.choices, required=False
    )
    note = serializers.CharField(
        required=False,
        allow_blank=True,
        trim_whitespace=False,
        max_length=FINDING_TRIAGE_NOTE_MAX_LENGTH,
    )
    assignee_id = serializers.UUIDField(required=False, allow_null=True)

    class JSONAPIMeta:
        resource_name = TRIAGE_RESOURCE

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        unknown = set(getattr(self, "initial_data", {}) or {}) - set(self.fields) - {
            "id",
            "type",
        }
        if unknown:
            raise serializers.ValidationError(f"Invalid fields: {sorted(unknown)}")
        if not attrs:
            raise serializers.ValidationError(
                "Send at least one of status, note or assignee_id."
            )
        return attrs


class FindingTriageBulkSerializer(BaseSerializerV1):
    """POST body of the bulk endpoint."""

    finding_uids = serializers.ListField(
        child=serializers.CharField(max_length=300),
        allow_empty=False,
        max_length=BULK_MAX_FINDINGS,
    )
    status = serializers.ChoiceField(choices=FindingTriage.Status.choices)
    note = serializers.CharField(
        required=False,
        allow_blank=True,
        trim_whitespace=False,
        max_length=FINDING_TRIAGE_NOTE_MAX_LENGTH,
    )

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}finding-triage-bulk"


class FindingTriageNoteSerializer(RLSSerializer):
    """Read serializer for notes."""

    author_id = serializers.UUIDField(read_only=True, allow_null=True)
    author_name = serializers.SerializerMethodField()
    triage_id = serializers.UUIDField(read_only=True)

    class Meta:
        model = FindingTriageNote
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "triage_id",
            "body",
            "status",
            "author_id",
            "author_name",
        ]

    class JSONAPIMeta:
        resource_name = NOTE_RESOURCE

    def get_author_name(self, obj: FindingTriageNote) -> str:
        author = obj.author
        if author is None:
            return ""
        return getattr(author, "name", "") or getattr(author, "email", "")


class FindingTriageNoteWriteSerializer(BaseSerializerV1):
    """POST / PATCH body of a note."""

    body = serializers.CharField(
        trim_whitespace=False, max_length=FINDING_TRIAGE_NOTE_MAX_LENGTH
    )

    class JSONAPIMeta:
        resource_name = NOTE_RESOURCE
