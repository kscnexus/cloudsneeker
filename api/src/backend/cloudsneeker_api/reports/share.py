"""Expiring public share links for report runs.

The raw token is ``secrets.token_urlsafe(32)`` and is returned exactly once.
Only its SHA-256 hex digest is stored, so a database leak never exposes a
usable link. Lookup is by digest (unique index) and the digest is compared
again with ``hmac.compare_digest``.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import Any

from api.db_router import MainRouter
from api.db_utils import rls_transaction
from cloudsneeker_api.models import ReportRun, ReportShareLink
from cloudsneeker_api.reports.catalog import FORMAT_JSON
from cloudsneeker_api.reports.runs import ReportRunError, read_report_json
from django.db.models import F
from django.utils import timezone

DEFAULT_TTL_HOURS = 72
MAX_TTL_HOURS = 24 * 30
TOKEN_BYTES = 32
# token_urlsafe(32) is 43 characters; bound input before hashing.
MAX_TOKEN_LENGTH = 128


class ShareLinkError(Exception):
    """Raised when a share link cannot be created or resolved.

    Attributes:
        code: Machine-readable reason (``not_found``, ``expired``, ``revoked``,
            ``not_ready``, ``invalid``).
    """

    def __init__(self, message: str, code: str = "invalid") -> None:
        super().__init__(message)
        self.code = code


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest stored for a raw token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    """Return a new random URL-safe token."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def create_share_link(
    *,
    tenant_id: str,
    run: ReportRun,
    created_by_id: str | None = None,
    expires_in_hours: int | None = None,
) -> tuple[ReportShareLink, str]:
    """Create a share link for a completed run.

    Args:
        tenant_id: Tenant UUID string.
        run: The run to share (must be completed with a JSON artifact).
        created_by_id: Requesting user id.
        expires_in_hours: Lifetime, 1 to ``MAX_TTL_HOURS`` (default 72).

    Returns:
        ``(link, raw_token)``; the raw token is not stored anywhere.

    Raises:
        ShareLinkError: The run is not shareable or the lifetime is invalid.
    """
    if run.status != ReportRun.Status.COMPLETED or FORMAT_JSON not in (run.artifacts or {}):
        raise ShareLinkError("Only completed reports can be shared.", code="not_ready")
    hours = DEFAULT_TTL_HOURS if expires_in_hours in (None, "") else expires_in_hours
    try:
        hours = int(hours)
    except (TypeError, ValueError) as exc:
        raise ShareLinkError("expires_in_hours must be an integer.") from exc
    if not 1 <= hours <= MAX_TTL_HOURS:
        raise ShareLinkError(f"expires_in_hours must be between 1 and {MAX_TTL_HOURS}.")
    token = generate_token()
    with rls_transaction(tenant_id):
        link = ReportShareLink.objects.create(
            tenant_id=tenant_id,
            report_run=run,
            token_hash=hash_token(token),
            expires_at=timezone.now() + timedelta(hours=hours),
            created_by_id=created_by_id,
        )
    return link, token


def revoke_share_link(link: ReportShareLink) -> ReportShareLink:
    """Revoke a link (idempotent)."""
    if link.revoked_at is None:
        link.revoked_at = timezone.now()
        link.save(update_fields=["revoked_at", "updated_at"])
    return link


def link_state(link: ReportShareLink, *, now=None) -> str:
    """Return ``active``, ``expired``, or ``revoked``."""
    moment = now or timezone.now()
    if link.revoked_at is not None:
        return "revoked"
    if link.expires_at <= moment:
        return "expired"
    return "active"


def resolve_share_token(token: str) -> tuple[ReportShareLink, dict[str, Any]]:
    """Resolve a public token to its report payload.

    Runs without a tenant context: the digest lookup uses the admin alias, then
    every further read happens inside that link's tenant RLS transaction.

    Args:
        token: Raw token from the URL.

    Returns:
        ``(link, report_json)``.

    Raises:
        ShareLinkError: Unknown, expired, or revoked token, or missing report.
    """
    if not token or len(token) > MAX_TOKEN_LENGTH:
        raise ShareLinkError("This link is invalid.", code="not_found")
    digest = hash_token(token)
    link = (
        ReportShareLink.objects.using(MainRouter.admin_db)
        .filter(token_hash=digest)
        .first()
    )
    if link is None or not hmac.compare_digest(link.token_hash, digest):
        raise ShareLinkError("This link is invalid.", code="not_found")
    state = link_state(link)
    if state == "revoked":
        raise ShareLinkError("This link has been revoked.", code="revoked")
    if state == "expired":
        raise ShareLinkError("This link has expired.", code="expired")

    tenant_id = str(link.tenant_id)
    with rls_transaction(tenant_id):
        run = ReportRun.objects.filter(tenant_id=tenant_id, id=link.report_run_id).first()
        if run is None:
            raise ShareLinkError("This report is no longer available.", code="not_found")
        try:
            payload = read_report_json(run)
        except ReportRunError as exc:
            raise ShareLinkError(str(exc), code="not_ready") from exc
        ReportShareLink.objects.filter(tenant_id=tenant_id, id=link.id).update(
            access_count=F("access_count") + 1,
            last_accessed_at=timezone.now(),
        )
    return link, payload
