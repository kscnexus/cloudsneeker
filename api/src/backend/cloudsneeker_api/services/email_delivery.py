"""Send email through the tenant's SMTP configuration."""

from __future__ import annotations

import logging
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTP, SMTP_SSL, SMTPException
from typing import Iterable

from api.db_utils import rls_transaction
from cloudsneeker_api.models import EmailDeliveryConfig

logger = logging.getLogger(__name__)


def get_email_delivery_config(tenant_id: str) -> EmailDeliveryConfig | None:
    """Return the tenant SMTP config when present and enabled."""
    with rls_transaction(tenant_id):
        return (
            EmailDeliveryConfig.objects.filter(tenant_id=tenant_id, enabled=True)
            .order_by("-updated_at")
            .first()
        )


def send_with_tenant_smtp(
    *,
    tenant_id: str,
    subject: str,
    message: str,
    recipient_list: Iterable[str],
    config: EmailDeliveryConfig | None = None,
    attachments: Iterable[tuple[str, bytes, str]] | None = None,
) -> int:
    """Send mail using the tenant SMTP settings.

    Args:
        tenant_id: Tenant UUID string.
        subject: Message subject.
        message: Plain-text body.
        recipient_list: Destination addresses; blanks are skipped.
        config: SMTP config to use instead of the tenant's stored one.
        attachments: Optional ``(filename, content, mime_type)`` files.

    Returns:
        Number of recipients the server accepted.

    Raises:
        ValueError: When SMTP is not configured for the tenant.
        SMTPException: When the SMTP server rejects the message.
    """
    recipients = [email for email in recipient_list if email]
    if not recipients:
        return 0

    smtp_config = config or get_email_delivery_config(tenant_id)
    if smtp_config is None:
        raise ValueError("Email delivery is not configured for this tenant.")

    files = list(attachments or [])
    if files:
        mime = MIMEMultipart()
        mime.attach(MIMEText(message, "plain", "utf-8"))
        for filename, content, mime_type in files:
            subtype = mime_type.split("/", 1)[1] if "/" in mime_type else "octet-stream"
            part = MIMEApplication(content, _subtype=subtype)
            part.add_header("Content-Disposition", "attachment", filename=filename)
            mime.attach(part)
    else:
        mime = MIMEText(message, "plain", "utf-8")
    mime["Subject"] = subject
    mime["From"] = smtp_config.from_email
    mime["To"] = ", ".join(recipients)

    try:
        if smtp_config.use_ssl:
            client: SMTP | SMTP_SSL = SMTP_SSL(
                host=smtp_config.host, port=smtp_config.port, timeout=30
            )
        else:
            client = SMTP(host=smtp_config.host, port=smtp_config.port, timeout=30)
            if smtp_config.use_tls:
                client.starttls()

        with client:
            if smtp_config.username:
                client.login(smtp_config.username, smtp_config.password or "")
            refused = client.sendmail(
                smtp_config.from_email, recipients, mime.as_string()
            )
    except SMTPException:
        logger.exception(
            "SMTP send failed for tenant=%s host=%s recipients=%s",
            tenant_id,
            smtp_config.host,
            len(recipients),
        )
        raise

    if refused:
        logger.error(
            "SMTP refused recipients for tenant=%s: %s",
            tenant_id,
            list(refused.keys()),
        )
    return len(recipients) - len(refused)
