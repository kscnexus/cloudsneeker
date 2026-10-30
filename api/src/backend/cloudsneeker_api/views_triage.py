"""Finding triage API (EB-010).

Routes (under ``/api/v1/``):

* ``finding-triages`` list (filters: status, status__in, assignee, check_id,
  check_id__in, provider, provider__in, finding_uid, finding_uid__in)
* ``finding-triages/{id}`` GET / PATCH (``id`` may also be a finding UID
  without ``/`` or ``.``)
* ``finding-triages/bulk`` POST (``finding_uids``, ``status``, ``note``; max 500)
* ``finding-triages/lookup?filter[finding_id__in]=...`` triage per finding row,
  used by the findings table to show status without changing the upstream
  findings API
* ``finding-triages/{id}/notes`` GET / POST, ``.../notes/{note_id}`` PATCH / DELETE
* ``findings/{finding_uid}/triage`` GET / PATCH (PATCH creates the row),
  ``.../triage/notes`` GET / POST and ``.../triage/notes/{note_id}`` PATCH /
  DELETE: the paths the inherited findings UI calls

Reading follows finding visibility; writing needs ``manage_scans``.
"""

from __future__ import annotations

from uuid import UUID

from api.base_views import BaseRLSViewSet
from api.filters import CharInFilter, ChoiceInFilter, UUIDInFilter
from api.rbac.permissions import Permissions
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX, FindingTriage
from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.serializers_triage import (
    TRIAGE_RESOURCE,
    FindingTriageBulkSerializer,
    FindingTriageNoteSerializer,
    FindingTriageNoteWriteSerializer,
    FindingTriageSerializer,
    FindingTriageUpdateSerializer,
)
from cloudsneeker_api.services.finding_triage import (
    LOOKUP_MAX_FINDINGS,
    TriageError,
    TriageNotFound,
    add_note,
    bulk_update_status,
    check_note_author,
    effective_status,
    findings_by_id,
    get_note,
    get_visible_triage,
    latest_findings,
    update_note,
    upsert_triage,
    visible_triages,
    with_note_summary,
)
from django_filters import rest_framework as filters
from drf_spectacular.utils import OpenApiResponse, extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import (
    MethodNotAllowed,
    NotFound,
    PermissionDenied,
    ValidationError,
)
from rest_framework.parsers import JSONParser
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response

LOOKUP_RESOURCE = f"{JSON_API_TYPE_PREFIX}finding-triage-lookups"
BULK_RESOURCE = f"{JSON_API_TYPE_PREFIX}finding-triage-bulk"
NOTE_ACTIONS = frozenset({"notes", "note_detail", "uid_notes", "uid_note_detail"})


class FindingTriageFilter(filters.FilterSet):
    status = filters.ChoiceFilter(choices=FindingTriage.Status.choices)
    status__in = ChoiceInFilter(
        field_name="status", lookup_expr="in", choices=FindingTriage.Status.choices
    )
    assignee = filters.UUIDFilter(field_name="assignee_id")
    check_id = filters.CharFilter()
    check_id__in = CharInFilter(field_name="check_id", lookup_expr="in")
    provider = filters.UUIDFilter(field_name="provider_id")
    provider__in = UUIDInFilter(field_name="provider_id", lookup_expr="in")
    finding_uid = filters.CharFilter()
    finding_uid__in = CharInFilter(field_name="finding_uid", lookup_expr="in")

    class Meta:
        model = FindingTriage
        fields = [
            "status",
            "assignee",
            "check_id",
            "provider",
            "finding_uid",
        ]


def _as_uuid(value) -> UUID | None:
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


def _csv_param(request, name: str) -> list[str]:
    raw = request.query_params.get(f"filter[{name}]", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


@extend_schema_view(
    list=extend_schema(tags=["Finding triage"], summary="List finding triage"),
    retrieve=extend_schema(tags=["Finding triage"], summary="Get a finding triage"),
    partial_update=extend_schema(
        tags=["Finding triage"], summary="Update a finding triage"
    ),
)
class FindingTriageViewSet(BaseRLSViewSet):
    """Triage status and notes per finding UID."""

    queryset = FindingTriage.objects.all()
    serializer_class = FindingTriageSerializer
    filterset_class = FindingTriageFilter
    parser_classes = [LenientJSONAPIParser, JSONParser]
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    ordering = ["-updated_at"]
    ordering_fields = ["updated_at", "inserted_at", "status_changed_at", "status"]

    def set_required_permissions(self):
        if self.request.method in SAFE_METHODS:
            self.required_permissions = []
        else:
            self.required_permissions = [Permissions.MANAGE_SCANS]

    def get_queryset(self):
        return visible_triages(str(self.request.tenant_id), self.user_role)

    def get_serializer_class(self):
        if self.action in NOTE_ACTIONS:
            return FindingTriageNoteSerializer
        return FindingTriageSerializer

    # --- helpers -----------------------------------------------------------

    @property
    def _tenant(self) -> str:
        return str(self.request.tenant_id)

    def _triage(self, pk=None, finding_uid=None) -> FindingTriage:
        if pk is not None and finding_uid is None and _as_uuid(pk) is None:
            finding_uid, pk = pk, None
        try:
            return get_visible_triage(
                self._tenant, self.user_role, pk=pk, finding_uid=finding_uid
            )
        except TriageNotFound as exc:
            raise NotFound(str(exc)) from exc

    def _triage_payload(self, triage: FindingTriage) -> dict:
        findings = latest_findings(self._tenant, self.user_role, [triage.finding_uid])
        context = {**self.get_serializer_context(), "findings": findings}
        return FindingTriageSerializer(triage, context=context).data

    def _reloaded(self, triage: FindingTriage) -> FindingTriage:
        return with_note_summary(FindingTriage.objects.filter(pk=triage.pk)).get()

    def _update(self, request, finding_uid: str) -> Response:
        serializer = FindingTriageUpdateSerializer(data=request.data or {})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            triage, created = upsert_triage(
                self._tenant,
                self.user_role,
                finding_uid,
                user_id=str(request.user.id),
                status=data.get("status"),
                note=data.get("note"),
                assignee_id=data["assignee_id"] if "assignee_id" in data else ...,
            )
        except TriageNotFound as exc:
            raise NotFound(str(exc)) from exc
        except TriageError as exc:
            raise ValidationError({"detail": str(exc)}, code=exc.code) from exc
        return Response(
            self._triage_payload(self._reloaded(triage)),
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    def _notes_response(self, request, triage: FindingTriage) -> Response:
        if request.method == "GET":
            notes = (
                triage.notes.select_related("author")
                .filter(tenant_id=triage.tenant_id)
                .order_by("-inserted_at")
            )
            page = self.paginate_queryset(notes)
            if page is not None:
                serializer = FindingTriageNoteSerializer(
                    page, many=True, context=self.get_serializer_context()
                )
                return self.get_paginated_response(serializer.data)
            serializer = FindingTriageNoteSerializer(
                notes, many=True, context=self.get_serializer_context()
            )
            return Response(serializer.data)
        body = FindingTriageNoteWriteSerializer(data=request.data or {})
        body.is_valid(raise_exception=True)
        try:
            note = add_note(triage, body.validated_data["body"], user_id=str(request.user.id))
        except TriageError as exc:
            raise ValidationError({"body": str(exc)}, code=exc.code) from exc
        return Response(
            FindingTriageNoteSerializer(note, context=self.get_serializer_context()).data,
            status=status.HTTP_201_CREATED,
        )

    def _note_detail_response(self, request, triage: FindingTriage, note_id) -> Response:
        try:
            note = get_note(triage, note_id)
            check_note_author(note, request.user.id)
        except TriageNotFound as exc:
            raise NotFound(str(exc)) from exc
        except PermissionError as exc:
            raise PermissionDenied(str(exc)) from exc
        if request.method == "DELETE":
            note.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        body = FindingTriageNoteWriteSerializer(data=request.data or {})
        body.is_valid(raise_exception=True)
        try:
            note = update_note(note, body.validated_data["body"])
        except TriageError as exc:
            raise ValidationError({"body": str(exc)}, code=exc.code) from exc
        return Response(
            FindingTriageNoteSerializer(note, context=self.get_serializer_context()).data
        )

    # --- collection and detail --------------------------------------------

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        rows = page if page is not None else list(queryset)
        findings = latest_findings(
            self._tenant, self.user_role, [row.finding_uid for row in rows]
        )
        context = {**self.get_serializer_context(), "findings": findings}
        serializer = FindingTriageSerializer(rows, many=True, context=context)
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)

    def retrieve(self, request, pk=None, *args, **kwargs):
        return Response(self._triage_payload(self._triage(pk)))

    def partial_update(self, request, pk=None, *args, **kwargs):
        # Read the body before anything else touches the renderer state.
        request.data  # noqa: B018
        triage = self._triage(pk)
        return self._update(request, triage.finding_uid)

    def create(self, request, *args, **kwargs):
        raise MethodNotAllowed(
            "POST", detail="PATCH findings/{finding_uid}/triage creates a triage."
        )

    def destroy(self, request, *args, **kwargs):
        raise MethodNotAllowed("DELETE")

    # --- collection actions -------------------------------------------------

    @extend_schema(
        tags=["Finding triage"],
        summary="Set one triage status on many findings",
        request=FindingTriageBulkSerializer,
        responses={200: OpenApiResponse(description="Counts and skipped UIDs")},
    )
    @action(detail=False, methods=["post"], url_path="bulk", url_name="bulk")
    def bulk(self, request):
        body = request.data or {}
        self.resource_name = False
        serializer = FindingTriageBulkSerializer(data=body)
        if not serializer.is_valid():
            raise ValidationError(serializer.errors)
        data = serializer.validated_data
        try:
            result = bulk_update_status(
                self._tenant,
                self.user_role,
                data["finding_uids"],
                status=data["status"],
                note=data.get("note"),
                user_id=str(request.user.id),
            )
        except TriageError as exc:
            raise ValidationError({"detail": str(exc)}, code=exc.code) from exc
        return Response(
            {
                "data": {
                    "type": BULK_RESOURCE,
                    "id": data["status"],
                    "attributes": {"status": data["status"], **result.to_dict()},
                }
            }
        )

    @extend_schema(
        tags=["Finding triage"],
        summary="Triage of specific finding rows",
        responses={200: OpenApiResponse(description="One entry per triaged finding")},
    )
    @action(detail=False, methods=["get"], url_path="lookup", url_name="lookup")
    def lookup(self, request):
        """``filter[finding_id__in]`` and / or ``filter[finding_uid__in]`` (max 200)."""
        self.resource_name = False
        finding_ids = [value for value in _csv_param(request, "finding_id__in") if _as_uuid(value)]
        finding_uids = _csv_param(request, "finding_uid__in")
        if len(finding_ids) + len(finding_uids) > LOOKUP_MAX_FINDINGS:
            raise ValidationError(
                {"detail": f"Look up at most {LOOKUP_MAX_FINDINGS} findings at once."}
            )
        rows = findings_by_id(self._tenant, self.user_role, finding_ids)
        latest = latest_findings(self._tenant, self.user_role, finding_uids)
        uids = {row.uid for row in rows.values()} | set(latest)
        triages = {
            triage.finding_uid: triage
            for triage in self.get_queryset().filter(finding_uid__in=list(uids))
        }
        documents = []
        entries = list(rows.items()) + [(row.id, row) for row in latest.values()]
        seen: set[str] = set()
        for finding_id, finding in entries:
            triage = triages.get(finding.uid)
            if triage is None or finding_id in seen:
                continue
            seen.add(finding_id)
            notes = int(getattr(triage, "notes_total", 0) or 0)
            documents.append(
                {
                    "type": LOOKUP_RESOURCE,
                    "id": finding_id,
                    "attributes": {
                        "finding_id": finding_id,
                        "finding_uid": finding.uid,
                        "triage_id": str(triage.id),
                        "triage_status": effective_status(triage, finding),
                        "triage_notes_count": notes,
                        "triage_has_note": notes > 0,
                        "assignee_id": (
                            str(triage.assignee_id) if triage.assignee_id else None
                        ),
                    },
                }
            )
        return Response({"data": documents})

    # --- notes by triage id ---------------------------------------------------

    @extend_schema(tags=["Finding triage"], summary="List or add triage notes")
    @action(detail=True, methods=["get", "post"], url_path="notes", url_name="notes")
    def notes(self, request, pk=None):
        request.data  # noqa: B018
        return self._notes_response(request, self._triage(pk))

    @extend_schema(tags=["Finding triage"], summary="Edit or delete a triage note")
    @action(
        detail=True,
        methods=["patch", "delete"],
        url_path=r"notes/(?P<note_id>[0-9a-fA-F-]{36})",
        url_name="note-detail",
    )
    def note_detail(self, request, pk=None, note_id=None):
        request.data  # noqa: B018
        return self._note_detail_response(request, self._triage(pk), note_id)

    # --- paths keyed by finding UID (``findings/{uid}/triage``) ---------------

    def uid_retrieve(self, request, finding_uid: str):
        """Triage of a finding UID; an untriaged visible finding reads as open."""
        try:
            return Response(self._triage_payload(self._triage(finding_uid=finding_uid)))
        except NotFound:
            pass
        finding = latest_findings(self._tenant, self.user_role, [finding_uid]).get(
            finding_uid
        )
        if finding is None:
            raise NotFound("Finding not found.")
        self.resource_name = False
        return Response(
            {
                "data": {
                    "type": TRIAGE_RESOURCE,
                    "id": None,
                    "attributes": {
                        "finding_uid": finding.uid,
                        "finding_id": finding.id,
                        "status": FindingTriage.Status.OPEN,
                        "stored_status": None,
                        "check_id": finding.check_id,
                        "provider_id": finding.provider_id,
                        "raw_finding_status": finding.status,
                        "triage_notes_count": 0,
                        "has_note": False,
                        "note_id": None,
                        "current_note": "",
                    },
                }
            }
        )

    def uid_update(self, request, finding_uid: str):
        request.data  # noqa: B018
        return self._update(request, finding_uid)

    def uid_notes(self, request, finding_uid: str):
        request.data  # noqa: B018
        if request.method == "GET":
            try:
                triage = self._triage(finding_uid=finding_uid)
            except NotFound:
                if finding_uid not in latest_findings(
                    self._tenant, self.user_role, [finding_uid]
                ):
                    raise
                return Response([])
            return self._notes_response(request, triage)
        try:
            triage = self._triage(finding_uid=finding_uid)
        except NotFound:
            # First note on an untriaged finding creates the triage row.
            try:
                triage, _ = upsert_triage(
                    self._tenant,
                    self.user_role,
                    finding_uid,
                    user_id=str(request.user.id),
                )
            except TriageNotFound as exc:
                raise NotFound(str(exc)) from exc
        return self._notes_response(request, triage)

    def uid_note_detail(self, request, finding_uid: str, note_id):
        request.data  # noqa: B018
        return self._note_detail_response(
            request, self._triage(finding_uid=finding_uid), note_id
        )
