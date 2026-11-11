"""One mutelist for Cloud Security, Application Security and Governance.

Upstream mute rules (``api.MuteRule``) hold finding UIDs. Upstream applies them
to the latest scan of each provider when a rule is created and to every new
provider scan. Cloudsneeker adds what the other two areas need:

* Application Security scans do not run the provider scan, so each one applies
  the enabled rules to its shared ``Finding`` rows (``reconcile_scan``) and to
  the posture rows of the target (``AppSecFinding.suppressed``).
* One provider holds many application targets, so "latest scan per provider"
  misses most of them. A rule change mutes the shared rows of the latest scan
  of every target and updates the posture rows (``sync_rule``).
* Governance findings have no ``Finding`` row. Their UIDs are stored in the
  rule like any other and read back by the governance list.
* ``create_area_mute_rule`` creates a rule from UIDs of any area after checking
  the role can see each finding. The upstream endpoint takes ``Finding`` ids,
  which governance findings do not have.

A muted finding is never deleted. It leaves the active views and stays
readable with ``filter[muted]=include`` (area lists) or
``filter[suppressed]=true`` (application posture).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from api.models import Finding, MuteRule, Role
from django.db.models import F
from django.utils import timezone

MUTE_SOURCE = "mute_rule"
MUTE_RULE_UID_MAX = 255
MAX_UIDS_PER_RULE = 500


class AreaMuteError(ValueError):
    """Bad request for an area mute rule."""


@dataclass
class AreaMuteResult:
    rule: MuteRule
    skipped_uids: list[str] = field(default_factory=list)


def muted_uid_map(tenant_id: str) -> dict[str, dict[str, Any]]:
    """Enabled mute rules by finding UID (first rule wins)."""
    muted: dict[str, dict[str, Any]] = {}
    rows = (
        MuteRule.objects.filter(tenant_id=tenant_id, enabled=True)
        .order_by("inserted_at")
        .values("id", "name", "reason", "inserted_at", "finding_uids")
    )
    for row in rows:
        for uid in row["finding_uids"] or []:
            muted.setdefault(
                uid,
                {
                    "rule_id": str(row["id"]),
                    "rule_name": row["name"],
                    "reason": row["reason"],
                    "muted_at": row["inserted_at"],
                },
            )
    return muted


def _suppression(entry: dict[str, Any]) -> dict[str, Any]:
    muted_at = entry.get("muted_at")
    return {
        "status": "muted",
        "source": MUTE_SOURCE,
        "rule_id": entry["rule_id"],
        "rule_name": entry["rule_name"],
        "reason": entry["reason"],
        "muted_at": muted_at.isoformat() if muted_at else None,
    }


def sync_appsec_suppression(
    tenant_id: str, *, target_id: str | None = None, using: str | None = None
) -> dict[str, int]:
    """Make ``AppSecFinding.suppressed`` follow the enabled mute rules.

    Rows suppressed by the scanner's own ignore rules are left alone; only
    rows this module muted are released when their rule goes away.
    """
    from cloudsneeker_api.models_appsec import AppSecFinding

    manager = AppSecFinding.objects.using(using) if using else AppSecFinding.objects
    muted = muted_uid_map(tenant_id)
    rows = manager.filter(tenant_id=tenant_id)
    if target_id:
        rows = rows.filter(target_id=target_id)

    suppressed = released = 0
    if muted:
        for row in rows.filter(uid__in=list(muted), suppressed=False).only(
            "id", "uid", "suppression"
        ):
            row.suppressed = True
            row.suppression = _suppression(muted[row.uid])
            row.save(update_fields=["suppressed", "suppression", "updated_at"])
            suppressed += 1
    stale = rows.filter(suppressed=True, suppression__source=MUTE_SOURCE)
    if muted:
        stale = stale.exclude(uid__in=list(muted))
    released = stale.update(suppressed=False, suppression={})
    return {"suppressed": suppressed, "released": released}


def latest_app_security_scan_ids(tenant_id: str) -> list[str]:
    from cloudsneeker_api.models import TrivyRun

    runs = (
        TrivyRun.objects.filter(
            tenant_id=tenant_id,
            status=TrivyRun.Status.COMPLETED,
            scan_id__isnull=False,
        )
        .order_by("target_id", F("finished_at").desc(nulls_last=True))
        .distinct("target_id")
        .values_list("scan_id", flat=True)
    )
    return [str(pk) for pk in runs]


def mute_shared_rows(
    tenant_id: str, scan_ids: Iterable[str], muted: dict[str, dict[str, Any]]
) -> int:
    """Mute shared ``Finding`` rows of the given scans (never unmutes)."""
    scan_ids = list(scan_ids)
    if not scan_ids or not muted:
        return 0
    changed = 0
    by_rule: dict[str, list[str]] = {}
    for uid, entry in muted.items():
        by_rule.setdefault(entry["rule_id"], []).append(uid)
    for rule_id, uids in by_rule.items():
        entry = muted[uids[0]]
        changed += Finding.all_objects.filter(
            tenant_id=tenant_id, scan_id__in=scan_ids, uid__in=uids, muted=False
        ).update(
            muted=True,
            muted_at=entry["muted_at"] or timezone.now(),
            muted_reason=entry["reason"],
        )
    return changed


def reconcile_scan(tenant_id: str, scan_id: str, target_id: str) -> dict[str, int]:
    """Apply enabled rules to one finished application scan."""
    from api.db_utils import rls_transaction

    with rls_transaction(tenant_id):
        muted = muted_uid_map(tenant_id)
        shared = mute_shared_rows(tenant_id, [scan_id], muted)
        posture = sync_appsec_suppression(tenant_id, target_id=target_id)
    return {"shared_muted": shared, **posture}


def sync_rule(tenant_id: str) -> dict[str, int]:
    """After a rule changes: latest application scans and posture rows."""
    muted = muted_uid_map(tenant_id)
    shared = mute_shared_rows(tenant_id, latest_app_security_scan_ids(tenant_id), muted)
    posture = sync_appsec_suppression(tenant_id)
    return {"shared_muted": shared, **posture}


# --- Creating a rule from area findings -------------------------------------


def _visible_finding_uids(tenant_id: str, role: Role, uids: list[str]) -> set[str]:
    from cloudsneeker_api.services.finding_triage import visible_findings

    return set(
        visible_findings(tenant_id, role)
        .filter(uid__in=uids)
        .values_list("uid", flat=True)
        .distinct()
    )


def _visible_governance_uids(tenant_id: str, role: Role, uids: list[str]) -> set[str]:
    from cloudsneeker_api.services.governance_findings import governance_findings

    wanted = set(uids)
    return {
        finding.uid
        for finding in governance_findings(tenant_id, role)
        if finding.uid in wanted
    }


def create_area_mute_rule(
    *,
    tenant_id: str,
    role: Role,
    user: Any,
    finding_uids: list[str],
    name: str,
    reason: str,
) -> AreaMuteResult:
    """Create one upstream mute rule for findings of any area."""
    from cloudsneeker_api.services.governance_findings import is_governance_uid

    uids = list(dict.fromkeys(str(uid) for uid in finding_uids if uid))
    if not uids:
        raise AreaMuteError("Select at least one finding.")
    if len(uids) > MAX_UIDS_PER_RULE:
        raise AreaMuteError(f"At most {MAX_UIDS_PER_RULE} findings per rule.")
    name = (name or "").strip()
    reason = (reason or "").strip()
    if len(name) < 3 or len(name) > 100:
        raise AreaMuteError("Name must be 3 to 100 characters.")
    if len(reason) < 3 or len(reason) > 500:
        raise AreaMuteError("Reason must be 3 to 500 characters.")

    governance = [uid for uid in uids if is_governance_uid(uid)]
    others = [uid for uid in uids if not is_governance_uid(uid)]
    visible = _visible_finding_uids(tenant_id, role, others) if others else set()
    if governance:
        visible |= _visible_governance_uids(tenant_id, role, governance)

    already = set(muted_uid_map(tenant_id))
    accepted = [
        uid
        for uid in uids
        if uid in visible and uid not in already and len(uid) <= MUTE_RULE_UID_MAX
    ]
    skipped = [uid for uid in uids if uid not in accepted]
    if not accepted:
        raise AreaMuteError(
            "None of the selected findings can be muted: they are already muted, "
            "not visible to your role, or no longer current."
        )

    rule = MuteRule.objects.create(
        tenant_id=tenant_id,
        name=name,
        reason=reason,
        enabled=True,
        created_by=user if getattr(user, "is_authenticated", False) else None,
        finding_uids=accepted,
    )
    _mute_cloud_rows(tenant_id, rule, others)
    sync_rule(tenant_id)
    return AreaMuteResult(rule=rule, skipped_uids=skipped)


def _mute_cloud_rows(tenant_id: str, rule: MuteRule, uids: list[str]) -> None:
    """Cloud rows: the latest scan of each provider, like the upstream create."""
    from api.models import Scan

    if not uids:
        return
    provider_ids = list(
        Finding.all_objects.filter(tenant_id=tenant_id, uid__in=uids)
        .values_list("scan__provider_id", flat=True)
        .distinct()
    )
    if not provider_ids:
        return
    latest = Scan.objects.filter(
        tenant_id=tenant_id, provider_id__in=provider_ids
    ).latest_ids_per_provider()
    Finding.all_objects.filter(
        tenant_id=tenant_id,
        scan_id__in=list(latest),
        uid__in=rule.finding_uids,
        muted=False,
    ).update(muted=True, muted_at=rule.inserted_at, muted_reason=rule.reason)
