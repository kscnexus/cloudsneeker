"""Email delivery of generated reports through the tenant's SMTP settings."""

from __future__ import annotations

import logging
import os
from typing import Any

from cloudsneeker_api.brand import brand
from cloudsneeker_api.models import ReportRun
from cloudsneeker_api.reports.catalog import (
    FORMAT_CONTENT_TYPES,
    FORMAT_PDF,
    get_report_type,
)
from cloudsneeker_api.reports.runs import ReportRunError, artifact_path
from cloudsneeker_api.reports.share import create_share_link
from cloudsneeker_api.services.email_delivery import send_with_tenant_smtp
from django.conf import settings

logger = logging.getLogger(__name__)

# Share links sent by email when the PDF is too large to attach.
EMAIL_LINK_TTL_HOURS = 24 * 7


def max_attachment_bytes() -> int:
    """Attachment size cap (``REPORT_EMAIL_MAX_ATTACHMENT_MB``, default 10 MB)."""
    try:
        megabytes = float(os.environ.get("REPORT_EMAIL_MAX_ATTACHMENT_MB", "10"))
    except ValueError:
        megabytes = 10.0
    return int(megabytes * 1024 * 1024)


def shared_report_url(token: str) -> str:
    """Return the public report URL for a share token."""
    base = (getattr(settings, "UI_BASE_URL", "") or "").rstrip("/")
    return f"{base}/shared-reports/{token}"


def in_app_report_url(run: ReportRun) -> str:
    """Return the signed-in report page URL of a run."""
    base = (getattr(settings, "UI_BASE_URL", "") or "").rstrip("/")
    return f"{base}/reports/{run.id}"


def build_email_body(run: ReportRun, *, link: str | None, attached: bool) -> str:
    """Return the plain-text body of a report email.

    Args:
        run: Completed run (its ``summary`` supplies headline and grade).
        link: Public link when the PDF is not attached.
        attached: Whether the PDF is attached.

    Returns:
        Message body.
    """
    summary = run.summary or {}
    name = get_report_type(run.report_type).name
    lines = [
        f"Your scheduled {name} report from {brand.name} is ready.",
        "",
        str(summary.get("headline") or ""),
        f"Grade: {summary.get('grade', 'N/A')}",
        "",
    ]
    if attached:
        lines.append("The PDF report is attached.")
    elif link:
        lines.append(f"The report is too large to attach. View it here: {link}")
        lines.append("This link expires in 7 days.")
    lines += ["", f"Open in {brand.name}: {in_app_report_url(run)}"]
    return "\n".join(line for line in lines if line is not None).strip()


def deliver_report_email(
    *, tenant_id: str, run: ReportRun, recipients: list[str]
) -> dict[str, Any]:
    """Email a completed run's PDF, or a share link when it exceeds the cap.

    Args:
        tenant_id: Tenant UUID string.
        run: Completed run.
        recipients: Destination addresses.

    Returns:
        ``{"delivery", "sent"}`` where ``delivery`` is ``no_recipients``,
        ``attachment``, ``link``, or ``failed``.
    """
    emails = [email for email in recipients if email]
    if not emails:
        return {"delivery": "no_recipients", "sent": 0}

    attachments: list[tuple[str, bytes, str]] = []
    link: str | None = None
    try:
        pdf = artifact_path(run, FORMAT_PDF)
    except ReportRunError:
        pdf = None
    if pdf is not None and pdf.stat().st_size <= max_attachment_bytes():
        attachments.append((pdf.name, pdf.read_bytes(), FORMAT_CONTENT_TYPES[FORMAT_PDF]))
    else:
        _, token = create_share_link(
            tenant_id=tenant_id,
            run=run,
            created_by_id=str(run.created_by_id) if run.created_by_id else None,
            expires_in_hours=EMAIL_LINK_TTL_HOURS,
        )
        link = shared_report_url(token)

    summary = run.summary or {}
    subject = f"[{brand.name}] {summary.get('title') or get_report_type(run.report_type).name}"
    try:
        sent = send_with_tenant_smtp(
            tenant_id=tenant_id,
            subject=subject,
            message=build_email_body(run, link=link, attached=bool(attachments)),
            recipient_list=emails,
            attachments=attachments,
        )
    except Exception:  # noqa: BLE001 - delivery failure must not fail the run
        logger.exception("Report email failed tenant=%s run=%s", tenant_id, run.id)
        return {"delivery": "failed", "sent": 0}
    return {"delivery": "attachment" if attachments else "link", "sent": sent}
