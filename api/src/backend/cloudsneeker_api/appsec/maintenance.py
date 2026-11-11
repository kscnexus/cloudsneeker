"""Background upkeep: rescoring and retention."""

from __future__ import annotations

import shutil
from datetime import timedelta
from typing import Any

DEFAULT_RAW_ARTIFACT_DAYS = 90
DEFAULT_FIXED_FINDINGS_DAYS = 365


def rescore(
    *,
    tenant_id: str,
    application_id: str | None = None,
    target_ids: list[str] | None = None,
) -> int:
    """Recompute priority and deadlines of a tenant's active findings.

    Args:
        tenant_id: Tenant.
        application_id: Limit to the targets of one application.
        target_ids: Limit to these targets.

    Returns:
        Number of findings updated.
    """
    from api.db_utils import rls_transaction
    from cloudsneeker_api.appsec.lifecycle import AppContext, rescore_findings
    from cloudsneeker_api.appsec.risk import merge_risk_config, merge_sla_days
    from cloudsneeker_api.models import AppSecFinding, AppSecSettings, TrivyTarget
    from django.utils import timezone

    with rls_transaction(tenant_id):
        settings_row = AppSecSettings.objects.filter(tenant_id=tenant_id).first()
        targets = TrivyTarget.objects.filter(tenant_id=tenant_id).select_related(
            "application"
        )
        if application_id:
            targets = targets.filter(application_id=application_id)
        if target_ids:
            targets = targets.filter(id__in=target_ids)
        contexts: dict[Any, AppContext] = {}
        for target in targets:
            application = target.application
            contexts[target.id] = (
                AppContext(
                    criticality=application.criticality,
                    environment=application.environment,
                    internet_exposed=application.internet_exposed,
                )
                if application
                else AppContext()
            )
        queryset = AppSecFinding.objects.filter(
            tenant_id=tenant_id, target_id__in=list(contexts)
        ).exclude(state="fixed")
        return rescore_findings(
            queryset=queryset,
            context_for_target=lambda target_id: contexts.get(target_id, AppContext()),
            risk_config=merge_risk_config(settings_row.risk if settings_row else None),
            sla_days=merge_sla_days(settings_row.sla_days if settings_row else None),
            now=timezone.now(),
        )


def apply_retention(tenant_id: str) -> dict[str, int]:
    """Delete a tenant's expired raw reports and long-fixed findings.

    Returns:
        ``{"artifacts", "findings"}`` counts removed.
    """
    from api.db_utils import rls_transaction
    from cloudsneeker_api.appsec import engine
    from cloudsneeker_api.models import AppSecFinding, AppSecSettings, TrivyRun
    from django.utils import timezone

    now = timezone.now()
    removed = {"artifacts": 0, "findings": 0}
    with rls_transaction(tenant_id):
        settings_row = AppSecSettings.objects.filter(tenant_id=tenant_id).first()
        retention = (settings_row.retention if settings_row else None) or {}
        artifact_days = int(
            retention.get("raw_artifact_days") or DEFAULT_RAW_ARTIFACT_DAYS
        )
        finding_days = int(
            retention.get("fixed_findings_days") or DEFAULT_FIXED_FINDINGS_DAYS
        )
        stale_runs = TrivyRun.objects.filter(
            tenant_id=tenant_id,
            inserted_at__lt=now - timedelta(days=artifact_days),
        ).exclude(artifact_path="")
        root = engine.artifact_root()
        for run in stale_runs.only("id", "artifact_path")[:5000]:
            shutil.rmtree(root / run.artifact_path, ignore_errors=True)
            removed["artifacts"] += 1
        stale_runs.update(artifact_path="")
        removed["findings"], _ = AppSecFinding.objects.filter(
            tenant_id=tenant_id,
            state="fixed",
            fixed_at__lt=now - timedelta(days=finding_days),
        ).delete()
    return removed


def apply_retention_all_tenants() -> dict[str, int]:
    """Apply retention to every tenant (Celery Beat)."""
    from api.db_router import MainRouter
    from api.models import Tenant

    totals = {"artifacts": 0, "findings": 0}
    tenant_ids = Tenant.objects.using(MainRouter.admin_db).values_list("id", flat=True)
    for tenant_id in tenant_ids:
        removed = apply_retention(str(tenant_id))
        for key, value in removed.items():
            totals[key] += value
    return totals
