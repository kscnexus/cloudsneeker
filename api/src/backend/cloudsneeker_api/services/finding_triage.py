"""Finding triage: status and note thread per finding UID.

Upstream ``Finding`` rows belong to one scan; ``Finding.uid`` is the identity
that stays the same across rescans, so triage is keyed by ``(tenant, uid)``.
Visibility follows findings: a role with ``unlimited_visibility`` sees every
UID of the tenant, any other role only the UIDs whose latest finding belongs
to one of its providers (``reports.access.visible_provider_ids``).

A ``resolved`` triage whose finding fails again in a scan newer than the
status change reads as ``reopened`` (``effective_status``). The stored status
is not rewritten on read; rescan automation that persists the transition is a
follow-up (see ``knowledge-base/finding-triage.md``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from api.models import Finding, Membership, Role, StatusChoices
from cloudsneeker_api.models import (
    FINDING_TRIAGE_NOTE_MAX_LENGTH,
    FindingTriage,
    FindingTriageNote,
)
from cloudsneeker_api.reports.access import visible_provider_ids
from django.db.models import Count, OuterRef, QuerySet, Subquery
from django.utils import timezone

BULK_MAX_FINDINGS = 500
LOOKUP_MAX_FINDINGS = 200
STATUS_VALUES = frozenset(FindingTriage.Status.values)

# Control characters other than tab and newline; notes are plain text.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


class TriageError(ValueError):
    """Invalid triage request (bad status, note, assignee or batch)."""

    def __init__(self, message: str, code: str = "invalid_triage") -> None:
        super().__init__(message)
        self.code = code


class TriageNotFound(LookupError):
    """The finding UID, triage or note is not visible to the requester."""


@dataclass(frozen=True)
class FindingSnapshot:
    """Latest finding row for a UID (used for denormalized fields)."""

    id: str
    uid: str
    check_id: str
    provider_id: str | None
    status: str
    muted: bool
    inserted_at: datetime | None


@dataclass
class BulkResult:
    """Outcome of a bulk status change."""

    created: int = 0
    updated: int = 0
    unchanged: int = 0
    skipped_uids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "created": self.created,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "skipped_uids": self.skipped_uids,
        }


def clean_note_body(body: Any) -> str:
    """Validate and normalize a plain-text note.

    Args:
        body: Raw note text.

    Returns:
        Stripped text without control characters.

    Raises:
        TriageError: Not text, empty, or longer than the limit.
    """
    if not isinstance(body, str):
        raise TriageError("Note must be text.", "invalid_note")
    cleaned = _CONTROL_CHARS.sub("", body).strip()
    if not cleaned:
        raise TriageError("Note cannot be empty.", "invalid_note")
    if len(cleaned) > FINDING_TRIAGE_NOTE_MAX_LENGTH:
        raise TriageError(
            f"Note cannot exceed {FINDING_TRIAGE_NOTE_MAX_LENGTH} characters.",
            "invalid_note",
        )
    return cleaned


def validate_status(status: Any) -> str:
    """Return ``status`` when it is a known triage status.

    Raises:
        TriageError: Unknown status.
    """
    if status not in STATUS_VALUES:
        raise TriageError(
            f"Unknown triage status. Use one of: {', '.join(sorted(STATUS_VALUES))}.",
            "invalid_status",
        )
    return status


def validate_assignee(tenant_id: str, assignee_id: Any) -> str | None:
    """Return the assignee id when the user is a member of the tenant.

    Raises:
        TriageError: The user is not a member of the tenant.
    """
    if assignee_id in (None, ""):
        return None
    if not Membership.objects.filter(
        tenant_id=tenant_id, user_id=str(assignee_id)
    ).exists():
        raise TriageError("Assignee must be a member of this tenant.", "invalid_assignee")
    return str(assignee_id)


def effective_status(triage: FindingTriage, finding: FindingSnapshot | None) -> str:
    """Status shown to users.

    ``resolved`` reads as ``reopened`` when the finding failed (unmuted) in a
    scan newer than the status change.
    """
    if (
        triage.status == FindingTriage.Status.RESOLVED
        and finding is not None
        and finding.status == StatusChoices.FAIL
        and not finding.muted
        and finding.inserted_at is not None
        and triage.status_changed_at is not None
        and finding.inserted_at > triage.status_changed_at
    ):
        return FindingTriage.Status.REOPENED
    return triage.status


def visible_findings(tenant_id: str, role: Role) -> QuerySet:
    """Findings the role can read (same rule as the upstream findings list)."""
    queryset = Finding.all_objects.filter(tenant_id=tenant_id)
    visible = visible_provider_ids(role)
    if visible is not None:
        queryset = queryset.filter(scan__provider_id__in=list(visible))
    return queryset


def visible_triages(tenant_id: str, role: Role) -> QuerySet:
    """Triage rows the role can read, with note count and latest note."""
    queryset = FindingTriage.objects.filter(tenant_id=tenant_id)
    visible = visible_provider_ids(role)
    if visible is not None:
        queryset = queryset.filter(provider_id__in=list(visible))
    return with_note_summary(queryset)


def with_note_summary(queryset: QuerySet) -> QuerySet:
    """Annotate ``notes_total``, ``latest_note_id`` and ``latest_note_body``."""
    latest = FindingTriageNote.objects.filter(triage_id=OuterRef("pk")).order_by(
        "-inserted_at"
    )
    return queryset.annotate(
        notes_total=Count("notes", distinct=True),
        latest_note_id=Subquery(latest.values("id")[:1]),
        latest_note_body=Subquery(latest.values("body")[:1]),
    )


def _snapshot(row: dict[str, Any]) -> FindingSnapshot:
    return FindingSnapshot(
        id=str(row["id"]),
        uid=row["uid"],
        check_id=row["check_id"],
        provider_id=str(row["scan__provider_id"]) if row["scan__provider_id"] else None,
        status=row["status"],
        muted=bool(row["muted"]),
        inserted_at=row["inserted_at"],
    )


_SNAPSHOT_FIELDS = (
    "id",
    "uid",
    "check_id",
    "scan__provider_id",
    "status",
    "muted",
    "inserted_at",
)


def latest_findings(
    tenant_id: str, role: Role, uids: Iterable[str]
) -> dict[str, FindingSnapshot]:
    """Latest visible finding per UID (one query, ``DISTINCT ON uid``)."""
    uid_list = sorted({uid for uid in uids if uid})
    if not uid_list:
        return {}
    rows = (
        visible_findings(tenant_id, role)
        .filter(uid__in=uid_list)
        .order_by("uid", "-inserted_at")
        .distinct("uid")
        .values(*_SNAPSHOT_FIELDS)
    )
    return {row["uid"]: _snapshot(row) for row in rows}


def findings_by_id(
    tenant_id: str, role: Role, finding_ids: Iterable[str]
) -> dict[str, FindingSnapshot]:
    """Visible finding rows by id."""
    ids = sorted({str(value) for value in finding_ids if value})
    if not ids:
        return {}
    rows = visible_findings(tenant_id, role).filter(id__in=ids).values(*_SNAPSHOT_FIELDS)
    return {str(row["id"]): _snapshot(row) for row in rows}


def get_visible_triage(tenant_id: str, role: Role, *, pk=None, finding_uid=None):
    """Return one triage row the role can read.

    Raises:
        TriageNotFound: No such row or not visible.
    """
    queryset = visible_triages(tenant_id, role)
    triage = (
        queryset.filter(pk=pk).first()
        if pk is not None
        else queryset.filter(finding_uid=finding_uid).first()
    )
    if triage is None:
        raise TriageNotFound("Finding triage not found.")
    return triage


def _apply_status(
    triage: FindingTriage, status: str | None, now: datetime
) -> bool:
    if status is None or status == triage.status:
        return False
    triage.status = status
    triage.status_changed_at = now
    return True


def upsert_triage(
    tenant_id: str,
    role: Role,
    finding_uid: str,
    *,
    user_id: str,
    status: str | None = None,
    note: str | None = None,
    assignee_id: Any = ...,
    source: str = FindingTriage.Source.MANUAL,
) -> tuple[FindingTriage, bool]:
    """Create or update the triage of one finding UID.

    Args:
        tenant_id: Tenant UUID string.
        role: Requesting user's role (visibility).
        finding_uid: Stable finding UID.
        user_id: Acting user.
        status: New status, or ``None`` to keep it.
        note: Optional note added to the thread.
        assignee_id: New assignee (``None`` clears it); omit to keep it.
        source: Where the change came from.

    Returns:
        ``(triage, created)``.

    Raises:
        TriageNotFound: No visible finding has this UID.
        TriageError: Invalid status, note or assignee.
    """
    if status is not None:
        validate_status(status)
    body = clean_note_body(note) if note not in (None, "") else None
    snapshot = latest_findings(tenant_id, role, [finding_uid]).get(finding_uid)
    if snapshot is None:
        raise TriageNotFound("Finding not found.")
    assignee = (
        validate_assignee(tenant_id, assignee_id) if assignee_id is not ... else ...
    )

    now = timezone.now()
    triage = (
        FindingTriage.objects.select_for_update()
        .filter(tenant_id=tenant_id, finding_uid=finding_uid)
        .first()
    )
    created = triage is None
    if created:
        triage = FindingTriage(
            tenant_id=tenant_id,
            finding_uid=finding_uid,
            status=status or FindingTriage.Status.OPEN,
            status_changed_at=now,
        )
        status_changed = status is not None
    else:
        status_changed = _apply_status(triage, status, now)
    triage.check_id = snapshot.check_id
    triage.provider_id = snapshot.provider_id
    triage.updated_by_id = user_id
    triage.source = source
    if assignee is not ...:
        triage.assignee_id = assignee
    triage.save()
    if body:
        FindingTriageNote.objects.create(
            tenant_id=tenant_id,
            triage=triage,
            author_id=user_id,
            body=body,
            status=triage.status if status_changed else "",
        )
    return triage, created


def bulk_update_status(
    tenant_id: str,
    role: Role,
    finding_uids: Any,
    *,
    status: Any,
    user_id: str,
    note: str | None = None,
) -> BulkResult:
    """Set one status on many finding UIDs.

    UIDs without a visible finding are skipped and listed in the result.

    Raises:
        TriageError: Empty or oversized batch, bad status or note.
    """
    if not isinstance(finding_uids, list) or not all(
        isinstance(uid, str) and uid for uid in finding_uids
    ):
        raise TriageError("finding_uids must be a list of finding UIDs.", "invalid_batch")
    uids = list(dict.fromkeys(finding_uids))
    if not uids:
        raise TriageError("finding_uids cannot be empty.", "invalid_batch")
    if len(uids) > BULK_MAX_FINDINGS:
        raise TriageError(
            f"At most {BULK_MAX_FINDINGS} findings can be triaged at once.",
            "batch_too_large",
        )
    validate_status(status)
    body = clean_note_body(note) if note not in (None, "") else None

    snapshots = latest_findings(tenant_id, role, uids)
    existing = {
        triage.finding_uid: triage
        for triage in FindingTriage.objects.select_for_update().filter(
            tenant_id=tenant_id, finding_uid__in=list(snapshots)
        )
    }
    now = timezone.now()
    result = BulkResult()
    notes: list[FindingTriageNote] = []
    for uid in uids:
        snapshot = snapshots.get(uid)
        if snapshot is None:
            result.skipped_uids.append(uid)
            continue
        triage = existing.get(uid)
        if triage is None:
            triage = FindingTriage(
                tenant_id=tenant_id,
                finding_uid=uid,
                status=status,
                status_changed_at=now,
            )
            result.created += 1
            changed = True
        else:
            changed = _apply_status(triage, status, now)
            if changed:
                result.updated += 1
            else:
                result.unchanged += 1
        triage.check_id = snapshot.check_id
        triage.provider_id = snapshot.provider_id
        triage.updated_by_id = user_id
        triage.source = FindingTriage.Source.BULK
        triage.save()
        if body:
            notes.append(
                FindingTriageNote(
                    tenant_id=tenant_id,
                    triage=triage,
                    author_id=user_id,
                    body=body,
                    status=status if changed else "",
                )
            )
    if notes:
        FindingTriageNote.objects.bulk_create(notes)
    return result


def add_note(triage: FindingTriage, body: Any, *, user_id: str) -> FindingTriageNote:
    """Append a note to a triage thread."""
    note = FindingTriageNote.objects.create(
        tenant_id=triage.tenant_id,
        triage=triage,
        author_id=user_id,
        body=clean_note_body(body),
    )
    FindingTriage.objects.filter(pk=triage.pk).update(
        updated_at=timezone.now(), updated_by_id=user_id
    )
    return note


def get_note(triage: FindingTriage, note_id) -> FindingTriageNote:
    """Return a note of the thread.

    Raises:
        TriageNotFound: The note is not in this thread.
    """
    note = FindingTriageNote.objects.filter(
        tenant_id=triage.tenant_id, triage_id=triage.pk, pk=note_id
    ).first()
    if note is None:
        raise TriageNotFound("Note not found.")
    return note


def check_note_author(note: FindingTriageNote, user_id: Any) -> None:
    """Only the author edits or deletes a note.

    Raises:
        PermissionError: Someone else wrote the note.
    """
    if str(note.author_id) != str(user_id):
        raise PermissionError("Only the author can change this note.")


def update_note(note: FindingTriageNote, body: Any) -> FindingTriageNote:
    """Replace the body of a note."""
    note.body = clean_note_body(body)
    note.save(update_fields=["body", "updated_at"])
    return note


def triage_counts(tenant_id: str, finding_uids: QuerySet | Iterable[str]) -> dict[str, int]:
    """Count triage rows by stored status for a set of finding UIDs.

    Args:
        tenant_id: Tenant UUID string.
        finding_uids: UIDs (a ``values("uid")`` queryset works as a subquery).

    Returns:
        Status to count, every status present (zero when unused).
    """
    counts = {value: 0 for value in FindingTriage.Status.values}
    rows = (
        FindingTriage.objects.filter(tenant_id=tenant_id, finding_uid__in=finding_uids)
        .values("status")
        .annotate(total=Count("id"))
    )
    for row in rows:
        counts[row["status"]] = row["total"]
    return counts
