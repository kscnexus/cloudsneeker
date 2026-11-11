"""Finding triage: status and note thread per finding UID.

Upstream ``Finding`` rows belong to one scan; ``Finding.uid`` is the identity
that stays the same across rescans, so triage is keyed by ``(tenant, uid)``.
Visibility follows findings: a role with ``unlimited_visibility`` sees every
UID of the tenant, any other role only the UIDs whose latest finding belongs
to one of its providers (``reports.access.visible_provider_ids``).

``risk_accepted`` (EB-019) carries a reason, the approving user and an
expiry date (default ``RISK_DEFAULT_DAYS``, at most ``RISK_MAX_DAYS`` ahead).
An hourly task (``expire_risk_acceptances``) reopens findings whose
acceptance has expired and emails the owner.

A ``resolved`` triage whose finding fails again in a scan newer than the
status change reads as ``reopened`` (``effective_status``). The stored status
is not rewritten on read; rescan automation that persists the transition is a
follow-up (see ``knowledge-base/finding-triage.md``).

Each triage row records its product area (``FindingTriage.Area``). Findings
from ``trivy_hub`` scans are Application Security; ``custodian-`` UIDs are
Cloud Governance matches with no ``Finding`` row
(``services/governance_findings.py``); everything else is Cloud Security.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from api.models import Finding, Membership, Role, StatusChoices
from cloudsneeker_api.models import (
    FINDING_TRIAGE_NOTE_MAX_LENGTH,
    FindingTriage,
    FindingTriageNote,
)
from cloudsneeker_api.reports.access import visible_provider_ids
from cloudsneeker_api.services.governance_findings import (
    governance_findings,
    is_governance_uid,
)
from django.db.models import Count, OuterRef, QuerySet, Subquery
from django.db.models.fields.json import KeyTextTransform
from django.utils import timezone

RISK_DEFAULT_DAYS = 90
RISK_MAX_DAYS = 365
RISK_REASON_MAX_LENGTH = 1000
BULK_MAX_FINDINGS = 500
LOOKUP_MAX_FINDINGS = 200
STATUS_VALUES = frozenset(FindingTriage.Status.values)
AREA_VALUES = frozenset(FindingTriage.Area.values)
# ``Scan.scanner_args["source"]`` of Application Security imports.
APP_SECURITY_SCAN_SOURCE = "trivy_hub"

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
    area: str = FindingTriage.Area.CLOUD


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


@dataclass(frozen=True)
class RiskAcceptance:
    """Reason and expiry sent with ``risk_accepted`` (``None`` = not sent)."""

    reason: str | None = None
    expires_on: date | None = None

    @property
    def sent(self) -> bool:
        return self.reason is not None or self.expires_on is not None


def clean_risk_acceptance(
    reason: Any = None, expires_on: Any = None, *, today: date | None = None
) -> RiskAcceptance:
    """Validate a risk acceptance reason and expiry date.

    Raises:
        TriageError: Reason too long, or expiry not between tomorrow and
            ``RISK_MAX_DAYS`` days ahead.
    """
    today = today or timezone.now().date()
    cleaned_reason = None
    if reason is not None:
        if not isinstance(reason, str):
            raise TriageError("Risk reason must be text.", "invalid_risk_reason")
        cleaned_reason = _CONTROL_CHARS.sub("", reason).strip()
        if len(cleaned_reason) > RISK_REASON_MAX_LENGTH:
            raise TriageError(
                f"Risk reason cannot exceed {RISK_REASON_MAX_LENGTH} characters.",
                "invalid_risk_reason",
            )
    if expires_on is not None:
        if isinstance(expires_on, str):
            try:
                expires_on = date.fromisoformat(expires_on)
            except ValueError as error:
                raise TriageError(
                    "risk_expires_on must be a date (YYYY-MM-DD).",
                    "invalid_risk_expiry",
                ) from error
        if expires_on <= today:
            raise TriageError(
                "The risk acceptance must expire after today.", "invalid_risk_expiry"
            )
        if expires_on > today + timedelta(days=RISK_MAX_DAYS):
            raise TriageError(
                f"A risk can be accepted for at most {RISK_MAX_DAYS} days.",
                "invalid_risk_expiry",
            )
    return RiskAcceptance(reason=cleaned_reason, expires_on=expires_on)


def _accept_risk(
    triage: FindingTriage,
    acceptance: RiskAcceptance,
    *,
    renewing: bool,
    note_body: str | None,
    user_id: str,
    now: datetime,
) -> None:
    """Record reason, approver and expiry on a ``risk_accepted`` triage.

    ``renewing`` is true when the triage was already accepted: it keeps the
    current reason and a future expiry unless new values are sent. The
    acting user becomes the approver.
    """
    today = now.date()
    if acceptance.reason is not None:
        triage.risk_reason = acceptance.reason
    elif note_body:
        triage.risk_reason = note_body[:RISK_REASON_MAX_LENGTH]
    elif not renewing:
        triage.risk_reason = ""
    if acceptance.expires_on is not None:
        triage.risk_expires_on = acceptance.expires_on
    elif not (renewing and triage.risk_expires_on and triage.risk_expires_on > today):
        triage.risk_expires_on = today + timedelta(days=RISK_DEFAULT_DAYS)
    triage.risk_approved_by_id = user_id
    triage.risk_approved_at = now
    triage.risk_expired_at = None


def _check_acceptance_status(target_status: str, acceptance: RiskAcceptance) -> None:
    if acceptance.sent and target_status != FindingTriage.Status.RISK_ACCEPTED:
        raise TriageError(
            "risk_reason and risk_expires_on apply only to the risk_accepted status.",
            "invalid_risk_acceptance",
        )


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
    queryset = FindingTriage.objects.filter(tenant_id=tenant_id).select_related(
        "risk_approved_by"
    )
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


def area_for_scan_source(source: str | None) -> str:
    """Product area of a finding from its scan's ``scanner_args["source"]``."""
    if source == APP_SECURITY_SCAN_SOURCE:
        return FindingTriage.Area.APPLICATION_SECURITY
    return FindingTriage.Area.CLOUD


def _snapshot(row: dict[str, Any]) -> FindingSnapshot:
    return FindingSnapshot(
        id=str(row["id"]),
        uid=row["uid"],
        check_id=row["check_id"],
        provider_id=str(row["scan__provider_id"]) if row["scan__provider_id"] else None,
        status=row["status"],
        muted=bool(row["muted"]),
        inserted_at=row["inserted_at"],
        area=area_for_scan_source(row.get("scan_source")),
    )


_SNAPSHOT_FIELDS = (
    "id",
    "uid",
    "check_id",
    "scan__provider_id",
    "status",
    "muted",
    "inserted_at",
    "scan_source",
)


def _with_scan_source(queryset: QuerySet) -> QuerySet:
    return queryset.annotate(
        scan_source=KeyTextTransform("source", "scan__scanner_args")
    )


def governance_snapshots(
    tenant_id: str, role: Role, uids: Iterable[str]
) -> dict[str, FindingSnapshot]:
    """Snapshots of visible governance matches (``custodian-`` UIDs)."""
    wanted = {uid for uid in uids if uid and is_governance_uid(uid)}
    if not wanted:
        return {}
    return {
        finding.uid: FindingSnapshot(
            id=finding.uid,
            uid=finding.uid,
            check_id=finding.rule_name[:100],
            provider_id=finding.provider_id,
            status=StatusChoices.FAIL,
            muted=False,
            inserted_at=finding.last_seen_at,
            area=FindingTriage.Area.GOVERNANCE,
        )
        for finding in governance_findings(tenant_id, role)
        if finding.uid in wanted
    }


def latest_findings(
    tenant_id: str, role: Role, uids: Iterable[str]
) -> dict[str, FindingSnapshot]:
    """Latest visible finding per UID (one query, ``DISTINCT ON uid``).

    Governance UIDs resolve against the latest run of their policy instead.
    """
    uid_set = {uid for uid in uids if uid}
    snapshots = governance_snapshots(tenant_id, role, uid_set)
    uid_list = sorted(uid for uid in uid_set if not is_governance_uid(uid))
    if not uid_list:
        return snapshots
    rows = (
        _with_scan_source(visible_findings(tenant_id, role))
        .filter(uid__in=uid_list)
        .order_by("uid", "-inserted_at")
        .distinct("uid")
        .values(*_SNAPSHOT_FIELDS)
    )
    snapshots.update({row["uid"]: _snapshot(row) for row in rows})
    return snapshots


def findings_by_id(
    tenant_id: str, role: Role, finding_ids: Iterable[str]
) -> dict[str, FindingSnapshot]:
    """Visible finding rows by id."""
    ids = sorted({str(value) for value in finding_ids if value})
    if not ids:
        return {}
    rows = (
        _with_scan_source(visible_findings(tenant_id, role))
        .filter(id__in=ids)
        .values(*_SNAPSHOT_FIELDS)
    )
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
    acceptance: RiskAcceptance | None = None,
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
        acceptance: Reason and expiry for ``risk_accepted`` (EB-019).

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

    acceptance = acceptance or RiskAcceptance()
    now = timezone.now()
    triage = (
        FindingTriage.objects.select_for_update()
        .filter(tenant_id=tenant_id, finding_uid=finding_uid)
        .first()
    )
    previous = triage.status if triage else None
    _check_acceptance_status(status or previous or FindingTriage.Status.OPEN, acceptance)
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
    triage.area = snapshot.area
    triage.updated_by_id = user_id
    triage.source = source
    if assignee is not ...:
        triage.assignee_id = assignee
    if triage.status == FindingTriage.Status.RISK_ACCEPTED and (
        status_changed or acceptance.sent
    ):
        _accept_risk(
            triage,
            acceptance,
            renewing=previous == FindingTriage.Status.RISK_ACCEPTED,
            note_body=body,
            user_id=user_id,
            now=now,
        )
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
    acceptance: RiskAcceptance | None = None,
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
    acceptance = acceptance or RiskAcceptance()
    _check_acceptance_status(status, acceptance)
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
        previous = triage.status if triage else None
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
        triage.area = snapshot.area
        triage.updated_by_id = user_id
        triage.source = FindingTriage.Source.BULK
        if status == FindingTriage.Status.RISK_ACCEPTED and (
            changed or acceptance.sent
        ):
            _accept_risk(
                triage,
                acceptance,
                renewing=previous == FindingTriage.Status.RISK_ACCEPTED,
                note_body=body,
                user_id=user_id,
                now=now,
            )
            if not changed:
                # Renewing an acceptance is an update.
                result.unchanged -= 1
                result.updated += 1
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
    counts = dict.fromkeys(FindingTriage.Status.values, 0)
    rows = (
        FindingTriage.objects.filter(tenant_id=tenant_id, finding_uid__in=finding_uids)
        .values("status")
        .annotate(total=Count("id"))
    )
    for row in rows:
        counts[row["status"]] = row["total"]
    return counts
