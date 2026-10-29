"""Report run lifecycle: enqueue, generate, store, and read artifacts.

Artifacts live on the output volume the API and workers already share
(``DJANGO_TMP_OUTPUT_DIRECTORY``, an EFS mount on ECS) under
``cloudsneeker-reports/<tenant_id>/<run_id>/``. Paths stored on the run are
relative to that root so a moved mount keeps working.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from api.db_utils import rls_transaction
from cloudsneeker_api.models import ReportRun
from cloudsneeker_api.reports.catalog import (
    FORMAT_JSON,
    filters_from_params,
    get_report_type,
    report_filename,
    validate_formats,
    validate_params,
)
from cloudsneeker_api.reports.data import assemble_report
from cloudsneeker_api.reports.render import get_renderer
from cloudsneeker_api.reports.schema import ReportData
from django.conf import settings
from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

REPORTS_DIRNAME = "cloudsneeker-reports"


class ReportRunError(Exception):
    """Raised when a report run cannot be created, generated, or read."""


def report_root() -> Path:
    """Return the directory that holds every tenant's report artifacts."""
    return Path(settings.DJANGO_TMP_OUTPUT_DIRECTORY) / REPORTS_DIRNAME


def run_directory(tenant_id: str, run_id: str) -> Path:
    """Return (without creating) the artifact directory of one run."""
    return report_root() / str(tenant_id) / str(run_id)


def enqueue_report_run(
    *,
    tenant_id: str,
    report_type: str,
    params: dict[str, Any] | None,
    formats: list[str] | None,
    created_by_id: str | None = None,
    trigger: str = ReportRun.Trigger.MANUAL,
    schedule_id: str | None = None,
    dispatch: bool = True,
) -> ReportRun:
    """Validate input, create a pending run, and enqueue generation on commit.

    Args:
        tenant_id: Tenant UUID string.
        report_type: Catalog key.
        params: Raw report parameters.
        formats: Requested formats (JSON is always added).
        created_by_id: Requesting user id.
        trigger: ``manual`` or ``scheduled``.
        schedule_id: Schedule that produced the run.
        dispatch: Enqueue the Celery task; ``False`` lets the caller generate
            the run inline (scheduled delivery).

    Returns:
        The pending ``ReportRun``.

    Raises:
        ReportParamsError: Invalid type, parameters, or formats.
    """
    get_report_type(report_type)
    normalized = validate_params(report_type, params)
    selected = validate_formats(formats)
    with rls_transaction(tenant_id):
        run = ReportRun.objects.create(
            tenant_id=tenant_id,
            report_type=report_type,
            params=normalized,
            formats=selected,
            status=ReportRun.Status.PENDING,
            trigger=trigger,
            created_by_id=created_by_id,
            schedule_id=schedule_id,
        )
    if dispatch:
        from cloudsneeker_api.tasks import generate_report_task

        run_id = str(run.id)
        transaction.on_commit(
            lambda: generate_report_task.delay(tenant_id=str(tenant_id), run_id=run_id)
        )
    return run


def run_summary(data: ReportData) -> dict[str, Any]:
    """Return the small summary stored on the run for list views and email."""
    return {
        "title": data.title,
        "headline": data.headline,
        "grade": data.grade,
        "score": data.score,
        "empty": data.is_empty,
        "severity_totals": data.severity_totals,
        "status_totals": data.status_totals,
    }


def write_artifacts(
    tenant_id: str, run_id: str, report_type: str, formats: list[str], data: ReportData
) -> tuple[dict[str, str], dict[str, int]]:
    """Render every format and write it under the run directory.

    Args:
        tenant_id: Tenant UUID string.
        run_id: Run UUID string.
        report_type: Catalog key (file name).
        formats: Formats to render.
        data: Assembled data.

    Returns:
        ``(relative paths by format, sizes by format)``.
    """
    directory = run_directory(tenant_id, run_id)
    directory.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    sizes: dict[str, int] = {}
    for fmt in formats:
        content = get_renderer(fmt)(data)
        filename = report_filename(report_type, fmt, data.generated_at)
        target = directory / filename
        target.write_bytes(content)
        paths[fmt] = str(target.relative_to(report_root()).as_posix())
        sizes[fmt] = len(content)
    return paths, sizes


def process_report_run(*, tenant_id: str, run_id: str) -> dict[str, Any]:
    """Generate a pending run's artifacts and mark it completed or failed.

    Args:
        tenant_id: Tenant UUID string.
        run_id: Run UUID string.

    Returns:
        ``{"status", "run_id"}``.

    Raises:
        ReportRunError: The run does not exist.
    """
    with rls_transaction(tenant_id):
        run = ReportRun.objects.filter(tenant_id=tenant_id, id=run_id).first()
        if run is None:
            raise ReportRunError(f"Report run {run_id} was not found.")
        if run.status == ReportRun.Status.COMPLETED:
            return {"status": run.status, "run_id": str(run_id)}
        run.status = ReportRun.Status.RUNNING
        run.started_at = timezone.now()
        run.error = ""
        run.save(update_fields=["status", "started_at", "error", "updated_at"])
        report_type = run.report_type
        params = dict(run.params or {})
        formats = list(run.formats or [FORMAT_JSON])

    try:
        with rls_transaction(tenant_id):
            data = assemble_report(tenant_id, report_type, filters_from_params(params))
        paths, sizes = write_artifacts(tenant_id, str(run_id), report_type, formats, data)
    except Exception as exc:  # noqa: BLE001 - every failure is recorded on the run
        logger.exception("Report generation failed tenant=%s run=%s", tenant_id, run_id)
        with rls_transaction(tenant_id):
            ReportRun.objects.filter(tenant_id=tenant_id, id=run_id).update(
                status=ReportRun.Status.FAILED,
                error=str(exc)[:4000],
                finished_at=timezone.now(),
                updated_at=timezone.now(),
            )
        return {"status": ReportRun.Status.FAILED, "run_id": str(run_id)}

    with rls_transaction(tenant_id):
        ReportRun.objects.filter(tenant_id=tenant_id, id=run_id).update(
            status=ReportRun.Status.COMPLETED,
            artifacts=paths,
            artifact_sizes=sizes,
            size_bytes=sum(sizes.values()),
            summary=run_summary(data),
            finished_at=timezone.now(),
            updated_at=timezone.now(),
        )
    return {"status": ReportRun.Status.COMPLETED, "run_id": str(run_id)}


def artifact_path(run: ReportRun, fmt: str) -> Path:
    """Return the absolute path of a run artifact, refusing paths outside root.

    Args:
        run: Completed run.
        fmt: Output format.

    Returns:
        Existing file path.

    Raises:
        ReportRunError: Not completed, format not generated, or file missing.
    """
    if run.status != ReportRun.Status.COMPLETED:
        raise ReportRunError("The report is not ready yet.")
    relative = (run.artifacts or {}).get(fmt)
    if not relative:
        raise ReportRunError(f"The report was not generated as {fmt}.")
    root = report_root().resolve()
    path = (root / relative).resolve()
    if root not in path.parents:
        raise ReportRunError("Invalid artifact path.")
    if not path.is_file():
        raise ReportRunError("The report file is no longer available.")
    return path


def read_report_json(run: ReportRun) -> dict[str, Any]:
    """Return the stored JSON payload of a completed run."""
    path = artifact_path(run, FORMAT_JSON)
    return json.loads(path.read_text(encoding="utf-8"))


def delete_run_artifacts(tenant_id: str, run_id: str) -> None:
    """Remove a run's artifact directory (best effort)."""
    directory = run_directory(tenant_id, run_id)
    if not directory.is_dir():
        return
    for child in directory.iterdir():
        try:
            child.unlink()
        except OSError:
            logger.warning("Could not delete report artifact %s", child)
    try:
        directory.rmdir()
    except OSError:
        logger.warning("Could not delete report directory %s", directory)
