"""Fold duplicate Application Security targets into one.

Earlier versions needed a second target to run static analysis on a
repository already scanned for dependencies, and one target per branch.
A repository target now runs static analysis itself (``config.sast``) and
scans extra branches (``config.branches``), so those duplicates can be
merged into one target without losing their history:

* Findings move to the kept target. A source that scanned the kept target's
  main branch keeps its findings on the main branch; one that scanned
  another branch keeps them under that branch, which is added to
  ``config.branches``.
* Runs move too. A static analysis run merged onto the main branch keeps its
  shared rows as the run's ``code_scan_id``.
* A static analysis source turns static analysis on for the kept target,
  with its rule sets, unless the kept target already runs it.
* Inventory versions of the source are dropped: only the kept target's main
  branch has an inventory.
* Report schedules that named the source name the kept target.

Triage follows the finding UID, which does not change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MAX_SOURCES = 100


class TargetMergeError(ValueError):
    """The targets cannot be merged."""


@dataclass
class MergePlan:
    """What a merge of one source does (computed before anything changes)."""

    source_id: str
    source_name: str
    finding_branch: str
    enable_sast: dict[str, Any] | None = None
    add_branch: str = ""
    conflicts: list[str] = field(default_factory=list)


def _main_branch(tenant_id: str, target) -> str:
    from cloudsneeker_api.reports.targets import target_branch

    return target_branch(tenant_id, target)


def plan_merge(tenant_id: str, dest, source) -> MergePlan:
    """Check one source against the kept target and describe the merge.

    Raises:
        TargetMergeError: Different repository, unsupported mode, or the
            same target.
    """
    from cloudsneeker_api.models import AppSecFinding, TrivyTarget

    if str(source.id) == str(dest.id):
        raise TargetMergeError("A target cannot be merged into itself.")
    if dest.mode not in (TrivyTarget.Mode.REPO, TrivyTarget.Mode.SAST):
        raise TargetMergeError("Only code repository targets can take merges.")
    if source.provider_id != dest.provider_id:
        raise TargetMergeError(
            f"'{source.name}' reads another repository; only targets of the same "
            "source can be merged."
        )
    allowed = {dest.mode}
    if dest.mode == TrivyTarget.Mode.REPO:
        allowed.add(TrivyTarget.Mode.SAST)
    if source.mode not in allowed:
        raise TargetMergeError(
            f"'{source.name}' is a {source.get_mode_display()} target and cannot "
            f"be merged into a {dest.get_mode_display()} target."
        )
    source_config = source.config if isinstance(source.config, dict) else {}
    dest_config = dest.config if isinstance(dest.config, dict) else {}
    if source_config.get("archive_b64") or not source_config.get("repository_url"):
        raise TargetMergeError(
            f"'{source.name}' scans an uploaded archive, not the repository."
        )

    dest_branch = _main_branch(tenant_id, dest)
    source_branch = _main_branch(tenant_id, source)
    same_branch = source_branch == dest_branch or not source_branch
    plan = MergePlan(
        source_id=str(source.id),
        source_name=source.name,
        finding_branch="" if same_branch else source_branch,
    )
    if not same_branch and source_branch not in (dest_config.get("branches") or []):
        plan.add_branch = source_branch
    if (
        source.mode == TrivyTarget.Mode.SAST
        and dest.mode == TrivyTarget.Mode.REPO
        and not isinstance(dest_config.get("sast"), dict)
    ):
        plan.enable_sast = {
            "rulesets": list(source_config.get("rulesets") or []),
            "exclude": list(source_config.get("exclude") or []),
        }

    source_prints = AppSecFinding.objects.filter(
        tenant_id=tenant_id, target=source
    ).values_list("fingerprint", flat=True)
    plan.conflicts = list(
        AppSecFinding.objects.filter(
            tenant_id=tenant_id,
            target=dest,
            branch=plan.finding_branch,
            fingerprint__in=source_prints,
        ).values_list("uid", flat=True)[:5]
    )
    return plan


def _apply_plan(tenant_id: str, dest, source, plan: MergePlan) -> None:
    from cloudsneeker_api.models import (
        AppSecFinding,
        AppSecSbom,
        ReportSchedule,
        TrivyRun,
        TrivyTarget,
    )
    from django.db.models import F

    AppSecFinding.objects.filter(tenant_id=tenant_id, target=source).update(
        target=dest, branch=plan.finding_branch
    )
    runs = TrivyRun.objects.filter(tenant_id=tenant_id, target=source)
    if source.mode == TrivyTarget.Mode.SAST and dest.mode == TrivyTarget.Mode.REPO:
        # Its shared rows are static analysis rows: they belong in code_scan_id.
        runs.filter(code_scan_id__isnull=True).update(
            code_scan_id=F("scan_id"), scan_id=None
        )
    runs.update(target=dest, branch=plan.finding_branch)
    AppSecSbom.objects.filter(tenant_id=tenant_id, target=source).delete()
    for schedule in ReportSchedule.objects.filter(
        tenant_id=tenant_id, params__target_id=str(source.id)
    ):
        schedule.params = {**schedule.params, "target_id": str(dest.id)}
        schedule.save(update_fields=["params", "updated_at"])
    if dest.application_id is None and source.application_id is not None:
        dest.application_id = source.application_id


def _check_sources_overlap(tenant_id: str, pairs) -> None:
    """Two sources may not bring the same finding to the same branch."""
    from cloudsneeker_api.models import AppSecFinding

    seen: dict[tuple[str, str], str] = {}
    for source, plan in pairs:
        prints = AppSecFinding.objects.filter(
            tenant_id=tenant_id, target=source
        ).values_list("fingerprint", flat=True)
        for fingerprint in prints.iterator(chunk_size=2000):
            key = (plan.finding_branch, fingerprint)
            other = seen.get(key)
            if other is not None and other != plan.source_name:
                raise TargetMergeError(
                    f"'{other}' and '{plan.source_name}' scan the same branch and "
                    "share findings; merge one of them only."
                )
            seen[key] = plan.source_name


def merge_targets(
    *, tenant_id: str, target_id: str, source_ids: list[str]
) -> dict[str, Any]:
    """Merge ``source_ids`` into ``target_id`` in one transaction.

    Returns:
        ``{"merged": [names], "branches": [added], "sast_enabled": bool}``.

    Raises:
        TargetMergeError: Any source cannot be merged; nothing changes.
    """
    from api.db_utils import rls_transaction
    from cloudsneeker_api.models import TrivyTarget
    from cloudsneeker_api.services.trivy import TrivyHubError, validate_target_config
    from cloudsneeker_api.services.trivy_schedule import delete_target_schedule
    from django.db import transaction

    ids = list(dict.fromkeys(str(item) for item in source_ids or []))
    if not ids:
        raise TargetMergeError("Name at least one target to merge.")
    if len(ids) > MAX_SOURCES:
        raise TargetMergeError(f"Merge at most {MAX_SOURCES} targets at a time.")

    with rls_transaction(tenant_id):
        dest = (
            TrivyTarget.objects.select_for_update()
            .filter(tenant_id=tenant_id, id=target_id)
            .first()
        )
        if dest is None:
            raise TargetMergeError("Target not found.")
        sources = list(
            TrivyTarget.objects.select_for_update().filter(
                tenant_id=tenant_id, id__in=ids
            )
        )
        if len(sources) != len(ids):
            raise TargetMergeError("One of the targets to merge was not found.")
        pairs = [(source, plan_merge(tenant_id, dest, source)) for source in sources]
        for _source, plan in pairs:
            if plan.conflicts:
                raise TargetMergeError(
                    f"'{plan.source_name}' has findings the kept target already "
                    "has on the same branch. Delete one of the two targets instead."
                )
        _check_sources_overlap(tenant_id, pairs)

        config = dict(dest.config or {})
        added: list[str] = []
        sast_enabled = False
        for _source, plan in pairs:
            if plan.add_branch and plan.add_branch not in added:
                added.append(plan.add_branch)
            if plan.enable_sast is not None and not sast_enabled:
                config["sast"] = plan.enable_sast
                sast_enabled = True
        if added:
            config["branches"] = [*(config.get("branches") or []), *added]
        try:
            config = validate_target_config(dest.mode, config, strict=False)
        except TrivyHubError as exc:
            raise TargetMergeError(str(exc)) from None

        with transaction.atomic():
            for source, plan in pairs:
                _apply_plan(tenant_id, dest, source, plan)
            dest.config = config
            dest.save(update_fields=["config", "application", "updated_at"])
            merged_names = [source.name for source in sources]
            merged_ids = [str(source.id) for source in sources]
            for source in sources:
                source.delete()

    for source_id in merged_ids:
        delete_target_schedule(source_id)
    return {"merged": merged_names, "branches": added, "sast_enabled": sast_enabled}
