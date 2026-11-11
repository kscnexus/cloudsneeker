"""Application Security scan history: archive runs past the retention window.

A daily Beat task (``cloudsneeker-archive-trivy-runs``) stamps
``TrivyRun.archived_at`` on runs older than ``APP_SECURITY_SCAN_ARCHIVE_DAYS``
(default 365). Archived runs stay in the database, with their linked Scan and
Findings untouched; the UI lists them apart from current history.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from datetime import timedelta

from api.db_router import MainRouter
from api.db_utils import rls_transaction
from cloudsneeker_api.models import TrivyRun
from django.utils import timezone

logger = logging.getLogger(__name__)

ARCHIVE_DAYS_ENV = "APP_SECURITY_SCAN_ARCHIVE_DAYS"
DEFAULT_ARCHIVE_DAYS = 365


def archive_days() -> int:
    """``APP_SECURITY_SCAN_ARCHIVE_DAYS``; values below 1 use the default."""
    try:
        days = int(os.environ.get(ARCHIVE_DAYS_ENV, DEFAULT_ARCHIVE_DAYS))
    except ValueError:
        return DEFAULT_ARCHIVE_DAYS
    return days if days >= 1 else DEFAULT_ARCHIVE_DAYS


def archive_tenant_runs(tenant_id: str, older_than_days: int) -> int:
    """Archive one tenant's runs started before the window; returns rows changed."""
    now = timezone.now()
    cutoff = now - timedelta(days=older_than_days)
    with rls_transaction(str(tenant_id), using=MainRouter.default_db):
        return (
            TrivyRun.objects.using(MainRouter.default_db)
            .filter(
                tenant_id=tenant_id,
                inserted_at__lt=cutoff,
                archived_at__isnull=True,
            )
            .update(archived_at=now)
        )


def archive_all_tenants(tenant_ids: Iterable[str], older_than_days: int) -> int:
    total = 0
    for tenant_id in tenant_ids:
        try:
            total += archive_tenant_runs(str(tenant_id), older_than_days)
        except Exception:
            logger.exception("Scan archiving failed for tenant=%s", tenant_id)
    return total
