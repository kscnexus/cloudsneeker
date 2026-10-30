"""Entitlements: the effective plan, features, limits and usage of a tenant.

``for_tenant(tenant_id)`` is the single read path used by the enforcement
middleware, ``GET /api/v1/entitlements`` and the operator console. It is
cached briefly per tenant and invalidated whenever a subscription or a plan
changes through :func:`update_subscription` or :func:`invalidate`.

Operator tables are not row-level security protected, so every query here
goes through ``MainRouter.admin_db`` (read at call time; tests patch it).
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from cloudsneeker_api.services import plan_catalog as catalog

logger = logging.getLogger(__name__)

CACHE_PREFIX = "cloudsneeker:entitlements:"
CACHE_SECONDS = 60
PLAN_CACHE_VERSION_KEY = "cloudsneeker:entitlements:plans-version"

# Usage key -> limit key it is measured against.
USAGE_LIMIT_KEYS = {
    "providers": catalog.LIMIT_PROVIDERS,
    "users": catalog.LIMIT_USERS,
    "application_security_targets": catalog.LIMIT_APPLICATION_SECURITY_TARGETS,
    "scans_this_month": catalog.LIMIT_SCANS_PER_MONTH,
    "report_schedules": catalog.LIMIT_REPORT_SCHEDULES,
}

# Subscription fields an operator may change, and how history records them.
EDITABLE_FIELDS = (
    "plan",
    "status",
    "starts_at",
    "ends_at",
    "trial_ends_at",
    "seats",
    "feature_overrides",
    "limit_overrides",
    "billing_source",
    "external_customer_id",
    "notes",
)
# Recorded in history by name only (free text).
NAME_ONLY_FIELDS = frozenset({"notes"})
DATE_FIELDS = frozenset({"starts_at", "ends_at", "trial_ends_at"})


class SubscriptionError(ValueError):
    """An invalid subscription change (bad plan, status or value)."""


@dataclass
class Entitlements:
    """Effective entitlements of one tenant (JSON-serialisable via ``as_dict``)."""

    tenant_id: str
    plan_code: str
    plan_name: str
    status: str
    effective_status: str
    read_only: bool
    features: list[str]
    limits: dict[str, int | None]
    starts_at: str | None = None
    ends_at: str | None = None
    trial_ends_at: str | None = None
    seats: int | None = None
    billing_source: str = catalog.BILLING_MANUAL
    subscription_id: str | None = None
    fallback: bool = False
    extra: dict = field(default_factory=dict)

    def has_feature(self, feature: str) -> bool:
        return feature in self.features

    def limit(self, key: str) -> int | None:
        return self.limits.get(key)

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("extra", None)
        return data


# --- Helpers ------------------------------------------------------------------


def _admin_db() -> str:
    from api.db_router import MainRouter

    return MainRouter.admin_db


def _iso(value: datetime | date | None) -> str | None:
    return value.isoformat() if value else None


def _now() -> datetime:
    from django.utils import timezone

    return timezone.now()


def month_start(now: datetime | None = None) -> datetime:
    """First instant of the current UTC month."""
    now = now or _now()
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def effective_features(plan_features: Any, overrides: Any) -> list[str]:
    """Plan features with ``feature_overrides`` applied (true adds, false removes)."""
    features = set(catalog.clean_features(plan_features))
    if isinstance(overrides, dict):
        for key, enabled in overrides.items():
            if key not in catalog.FEATURE_KEYS:
                continue
            if enabled:
                features.add(key)
            else:
                features.discard(key)
    return [key for key in catalog.FEATURE_KEYS if key in features]


def effective_limits(
    plan_limits: Any, overrides: Any, seats: int | None = None
) -> dict[str, int | None]:
    """Plan limits, then ``seats`` as the user limit, then ``limit_overrides``.

    A missing key or ``None`` means unlimited.
    """
    base = plan_limits if isinstance(plan_limits, dict) else {}
    limits: dict[str, int | None] = {}
    for key in catalog.LIMIT_KEYS:
        value = base.get(key)
        limits[key] = int(value) if isinstance(value, int) and value >= 0 else None
    if seats:
        limits[catalog.LIMIT_USERS] = int(seats)
    if isinstance(overrides, dict):
        for key in catalog.LIMIT_KEYS:
            if key not in overrides:
                continue
            value = overrides[key]
            limits[key] = (
                int(value)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0
                else None
            )
    return limits


def effective_status(
    status: str,
    ends_at: datetime | None,
    trial_ends_at: datetime | None,
    now: datetime | None = None,
) -> str:
    """Stored status, or ``expired`` when its end date has already passed.

    The daily task writes ``expired``; this keeps enforcement exact between
    runs.
    """
    now = now or _now()
    if status not in catalog.EXPIRABLE_STATUSES:
        return status
    if ends_at and ends_at <= now:
        return catalog.STATUS_EXPIRED
    if status == catalog.STATUS_TRIAL and trial_ends_at and trial_ends_at <= now:
        return catalog.STATUS_EXPIRED
    return status


def is_read_only(status: str) -> bool:
    return status in catalog.INACTIVE_STATUSES


def build_entitlements(tenant_id: str, subscription, plan) -> Entitlements:
    """Entitlements from a subscription row and its plan."""
    status = effective_status(
        subscription.status, subscription.ends_at, subscription.trial_ends_at
    )
    return Entitlements(
        tenant_id=str(tenant_id),
        plan_code=plan.code,
        plan_name=plan.name,
        status=subscription.status,
        effective_status=status,
        read_only=is_read_only(status),
        features=effective_features(plan.features, subscription.feature_overrides),
        limits=effective_limits(
            plan.limits, subscription.limit_overrides, subscription.seats
        ),
        starts_at=_iso(subscription.starts_at),
        ends_at=_iso(subscription.ends_at),
        trial_ends_at=_iso(subscription.trial_ends_at),
        seats=subscription.seats,
        billing_source=subscription.billing_source,
        subscription_id=str(subscription.id),
    )


def fallback_entitlements(tenant_id: str) -> Entitlements:
    """Unlimited, all-feature entitlements used when the lookup fails (fail open)."""
    legacy = catalog.DEFAULT_PLANS_BY_CODE[catalog.LEGACY_PLAN_CODE]
    return Entitlements(
        tenant_id=str(tenant_id),
        plan_code=legacy["code"],
        plan_name=legacy["name"],
        status=catalog.STATUS_ACTIVE,
        effective_status=catalog.STATUS_ACTIVE,
        read_only=False,
        features=list(catalog.FEATURE_KEYS),
        limits=dict.fromkeys(catalog.LIMIT_KEYS),
        fallback=True,
    )


# --- Plans and subscriptions ----------------------------------------------------


def get_or_create_plan(code: str):
    """The plan ``code``; a missing default plan is created from the catalogue."""
    from cloudsneeker_api.models import Plan

    alias = _admin_db()
    plan = Plan.objects.using(alias).filter(code=code).first()
    if plan is not None:
        return plan
    definition = catalog.DEFAULT_PLANS_BY_CODE.get(code)
    if definition is None:
        return None
    plan, _ = Plan.objects.using(alias).get_or_create(
        code=code,
        defaults={key: value for key, value in definition.items() if key != "code"},
    )
    return plan


def ensure_subscription(tenant_id: str):
    """The tenant's subscription, created on the default plan when missing.

    New tenants get ``CLOUDSNEEKER_DEFAULT_PLAN`` (default ``legacy``) and
    status ``active``, so no upstream signal is needed. An unknown default
    plan code falls back to ``legacy``.
    """
    from cloudsneeker_api.models import Subscription, SubscriptionEvent
    from django.db import IntegrityError, transaction

    alias = _admin_db()
    subscription = (
        Subscription.objects.using(alias)
        .select_related("plan")
        .filter(tenant_id=tenant_id)
        .first()
    )
    if subscription is not None:
        return subscription

    plan = get_or_create_plan(catalog.default_plan_code()) or get_or_create_plan(
        catalog.LEGACY_PLAN_CODE
    )
    try:
        with transaction.atomic(using=alias):
            subscription = Subscription.objects.using(alias).create(
                tenant_id=tenant_id,
                plan=plan,
                status=catalog.STATUS_ACTIVE,
                starts_at=_now(),
                billing_source=catalog.BILLING_MANUAL,
            )
            SubscriptionEvent.objects.using(alias).create(
                tenant_id=tenant_id,
                action="created",
                source="system",
                changes={"plan": {"from": None, "to": plan.code}},
            )
    except IntegrityError:
        # Created concurrently, or the tenant does not exist.
        subscription = (
            Subscription.objects.using(alias)
            .select_related("plan")
            .filter(tenant_id=tenant_id)
            .first()
        )
        if subscription is None:
            raise
    return subscription


def _cache():
    from django.core.cache import cache

    return cache


def _cache_key(tenant_id: str) -> str:
    version = _cache().get(PLAN_CACHE_VERSION_KEY, 0)
    return f"{CACHE_PREFIX}{version}:{tenant_id}"


def invalidate(tenant_id: str | None = None) -> None:
    """Drop cached entitlements for one tenant, or for all (plan changes)."""
    try:
        cache = _cache()
        if tenant_id is None:
            try:
                cache.incr(PLAN_CACHE_VERSION_KEY)
            except ValueError:
                cache.set(PLAN_CACHE_VERSION_KEY, 1, None)
            return
        cache.delete(_cache_key(str(tenant_id)))
    except Exception:
        logger.exception("Entitlements cache invalidation failed")


def for_tenant(tenant_id: str, use_cache: bool = True) -> Entitlements:
    """Effective entitlements of ``tenant_id`` (plan plus overrides), cached.

    Raises on database errors; callers that must fail open catch them.
    """
    tenant_id = str(tenant_id)
    key = _cache_key(tenant_id) if use_cache else None
    if key:
        cached = _cache().get(key)
        if isinstance(cached, dict):
            return Entitlements(**cached)
    subscription = ensure_subscription(tenant_id)
    entitlements = build_entitlements(tenant_id, subscription, subscription.plan)
    if key:
        _cache().set(key, entitlements.as_dict(), CACHE_SECONDS)
    return entitlements


# --- Usage ----------------------------------------------------------------------


def _grouped_counts(queryset, tenant_ids) -> dict[str, int]:
    from django.db.models import Count

    if tenant_ids is not None:
        queryset = queryset.filter(tenant_id__in=list(tenant_ids))
    rows = queryset.values("tenant_id").annotate(total=Count("id")).order_by()
    return {str(row["tenant_id"]): row["total"] for row in rows}


def usage_by_tenant(
    tenant_ids=None, now: datetime | None = None, include_findings: bool = False
) -> dict[str, dict[str, int | None]]:
    """Usage counts per tenant id, from existing tables in a few grouped queries.

    ``users`` counts members plus pending invitations, since both take a seat.
    Assistant requests are not recorded anywhere yet and are reported as
    ``None``.
    """
    from api.models import Finding, Invitation, Membership, Provider, Scan
    from cloudsneeker_api.models import ReportRun, ReportSchedule, TrivyTarget

    alias = _admin_db()
    start = month_start(now)
    providers = _grouped_counts(Provider.objects.using(alias).all(), tenant_ids)
    members = _grouped_counts(Membership.objects.using(alias).all(), tenant_ids)
    invitations = _grouped_counts(
        Invitation.objects.using(alias).filter(state=Invitation.State.PENDING),
        tenant_ids,
    )
    targets = _grouped_counts(TrivyTarget.objects.using(alias).all(), tenant_ids)
    schedules = _grouped_counts(ReportSchedule.objects.using(alias).all(), tenant_ids)
    scans = _grouped_counts(
        Scan.all_objects.using(alias).filter(inserted_at__gte=start), tenant_ids
    )
    reports = _grouped_counts(
        ReportRun.objects.using(alias).filter(inserted_at__gte=start), tenant_ids
    )
    findings = (
        _grouped_counts(
            Finding.all_objects.using(alias).filter(inserted_at__gte=start),
            tenant_ids,
        )
        if include_findings
        else {}
    )

    if tenant_ids is None:
        from api.models import Tenant

        tenant_ids = Tenant.objects.using(alias).values_list("id", flat=True)

    result: dict[str, dict[str, int | None]] = {}
    for raw_id in tenant_ids:
        tenant_id = str(raw_id)
        counts: dict[str, int | None] = {
            "providers": providers.get(tenant_id, 0),
            "members": members.get(tenant_id, 0),
            "pending_invitations": invitations.get(tenant_id, 0),
            "users": members.get(tenant_id, 0) + invitations.get(tenant_id, 0),
            "application_security_targets": targets.get(tenant_id, 0),
            "report_schedules": schedules.get(tenant_id, 0),
            "scans_this_month": scans.get(tenant_id, 0),
            "reports_this_month": reports.get(tenant_id, 0),
            "seeker_ai_requests_this_month": None,
        }
        if include_findings:
            counts["findings_this_month"] = findings.get(tenant_id, 0)
        result[tenant_id] = counts
    return result


def usage_for_tenant(tenant_id: str) -> dict[str, int | None]:
    return usage_by_tenant([str(tenant_id)])[str(tenant_id)]


def over_limit_keys(
    usage: dict[str, int | None], limits: dict[str, int | None]
) -> list[str]:
    """Limit keys whose usage is above the limit (``None`` limits never are)."""
    over = []
    for usage_key, limit_key in USAGE_LIMIT_KEYS.items():
        limit = limits.get(limit_key)
        used = usage.get(usage_key)
        if limit is not None and used is not None and used > limit:
            over.append(limit_key)
    return over


def last_activity_by_tenant(tenant_ids=None) -> dict[str, str | None]:
    """Latest audit event or scan per tenant (ISO timestamps)."""
    from api.models import Scan
    from cloudsneeker_api.models import AuditEvent
    from django.db.models import Max

    alias = _admin_db()
    latest: dict[str, datetime] = {}
    for queryset in (
        AuditEvent.objects.using(alias).all(),
        Scan.all_objects.using(alias).all(),
    ):
        if tenant_ids is not None:
            queryset = queryset.filter(tenant_id__in=list(tenant_ids))
        rows = queryset.values("tenant_id").annotate(last=Max("inserted_at")).order_by()
        for row in rows:
            tenant_id = str(row["tenant_id"])
            if row["last"] and (
                tenant_id not in latest or row["last"] > latest[tenant_id]
            ):
                latest[tenant_id] = row["last"]
    return {tenant_id: value.isoformat() for tenant_id, value in latest.items()}


# --- Changes ----------------------------------------------------------------------


def _parse_datetime(name: str, value: Any) -> datetime | None:
    from django.utils import timezone
    from django.utils.dateparse import parse_date, parse_datetime

    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value)
        parsed = parse_datetime(text)
        if parsed is None:
            day = parse_date(text)
            if day is None:
                raise SubscriptionError(f"'{name}' must be an ISO date or datetime.")
            parsed = datetime.combine(day, datetime.min.time())
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, UTC)
    return parsed


def _clean_feature_overrides(value: Any) -> dict[str, bool]:
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise SubscriptionError("'feature_overrides' must be an object.")
    unknown = [key for key in value if key not in catalog.FEATURE_KEYS]
    if unknown:
        raise SubscriptionError(f"Unknown feature keys: {', '.join(sorted(unknown))}.")
    return {key: bool(value[key]) for key in catalog.FEATURE_KEYS if key in value}


def _clean_limit_overrides(value: Any) -> dict[str, int | None]:
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise SubscriptionError("'limit_overrides' must be an object.")
    unknown = [key for key in value if key not in catalog.LIMIT_KEYS]
    if unknown:
        raise SubscriptionError(f"Unknown limit keys: {', '.join(sorted(unknown))}.")
    try:
        return catalog.clean_limits(value)
    except ValueError as error:
        raise SubscriptionError(str(error)) from None


def clean_subscription_changes(data: dict) -> dict[str, Any]:
    """Validate an operator PATCH body into model values (``plan`` as a Plan)."""
    from cloudsneeker_api.models import Plan

    cleaned: dict[str, Any] = {}
    for name in EDITABLE_FIELDS:
        if name not in data:
            continue
        value = data[name]
        if name == "plan":
            code = value.get("id") if isinstance(value, dict) else value
            plan = (
                Plan.objects.using(_admin_db()).filter(code=str(code or "")).first()
                or Plan.objects.using(_admin_db()).filter(id=_as_uuid(code)).first()
            )
            if plan is None:
                raise SubscriptionError("Unknown plan.")
            cleaned[name] = plan
        elif name == "status":
            if value not in dict(catalog.STATUS_CHOICES):
                raise SubscriptionError("Unknown status.")
            cleaned[name] = value
        elif name == "billing_source":
            if value not in dict(catalog.BILLING_SOURCE_CHOICES):
                raise SubscriptionError("Unknown billing source.")
            cleaned[name] = value
        elif name in DATE_FIELDS:
            cleaned[name] = _parse_datetime(name, value)
        elif name == "seats":
            if value in (None, ""):
                cleaned[name] = None
            else:
                if isinstance(value, bool):
                    raise SubscriptionError("'seats' must be a number.")
                try:
                    seats = int(value)
                except (TypeError, ValueError):
                    raise SubscriptionError("'seats' must be a number.") from None
                if seats < 0:
                    raise SubscriptionError("'seats' must be a positive number.")
                cleaned[name] = seats or None
        elif name == "feature_overrides":
            cleaned[name] = _clean_feature_overrides(value)
        elif name == "limit_overrides":
            cleaned[name] = _clean_limit_overrides(value)
        else:
            cleaned[name] = "" if value is None else str(value)
    return cleaned


def _as_uuid(value: Any):
    from uuid import UUID

    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


def _history_value(name: str, value: Any) -> Any:
    if name == "plan":
        return getattr(value, "code", value)
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def update_subscription(
    tenant_id: str,
    data: dict,
    actor_id: str | None = None,
    actor_email: str = "",
    source: str = "operator",
):
    """Apply a validated change and write a ``SubscriptionEvent``.

    Returns:
        ``(subscription, changed_field_names)``. No event is written when
        nothing changed.
    """
    from cloudsneeker_api.models import Subscription, SubscriptionEvent
    from django.db import transaction

    cleaned = clean_subscription_changes(data)
    alias = _admin_db()
    ensure_subscription(tenant_id)
    with transaction.atomic(using=alias):
        subscription = (
            Subscription.objects.using(alias)
            .select_for_update()
            .select_related("plan")
            .get(tenant_id=tenant_id)
        )
        changes: dict[str, Any] = {}
        for name, value in cleaned.items():
            current = (
                subscription.plan if name == "plan" else getattr(subscription, name)
            )
            same = current.id == value.id if name == "plan" else current == value
            if same:
                continue
            if name in NAME_ONLY_FIELDS:
                changes[name] = {"changed": True}
            else:
                changes[name] = {
                    "from": _history_value(name, current),
                    "to": _history_value(name, value),
                }
            setattr(subscription, name, value)
        if changes:
            subscription.save(using=alias)
            SubscriptionEvent.objects.using(alias).create(
                tenant_id=tenant_id,
                action="updated",
                source=source,
                changes=changes,
                actor_id=_as_uuid(actor_id),
                actor_email=(actor_email or "")[:254],
            )
    invalidate(tenant_id)
    return subscription, sorted(changes)


def expire_subscriptions(now: datetime | None = None) -> int:
    """Move subscriptions whose end date passed to ``expired``; returns the count."""
    from cloudsneeker_api.models import Subscription, SubscriptionEvent
    from django.db import transaction
    from django.db.models import Q

    now = now or _now()
    alias = _admin_db()
    due = (
        Subscription.objects.using(alias)
        .filter(status__in=catalog.EXPIRABLE_STATUSES)
        .filter(
            Q(ends_at__lte=now) | Q(status=catalog.STATUS_TRIAL, trial_ends_at__lte=now)
        )
    )
    expired = 0
    for subscription in due:
        with transaction.atomic(using=alias):
            previous = subscription.status
            subscription.status = catalog.STATUS_EXPIRED
            subscription.save(using=alias, update_fields=["status", "updated_at"])
            SubscriptionEvent.objects.using(alias).create(
                tenant_id=subscription.tenant_id,
                action="expired",
                source="system",
                changes={"status": {"from": previous, "to": catalog.STATUS_EXPIRED}},
            )
        invalidate(str(subscription.tenant_id))
        expired += 1
    return expired


def snapshot_usage(day: date | None = None) -> int:
    """Write (or refresh) today's ``UsageSnapshot`` for every tenant."""
    from cloudsneeker_api.models import UsageSnapshot

    now = _now()
    day = day or now.date()
    alias = _admin_db()
    written = 0
    for tenant_id, counts in usage_by_tenant(now=now, include_findings=True).items():
        try:
            UsageSnapshot.objects.using(alias).update_or_create(
                tenant_id=tenant_id, date=day, defaults={"counts": counts}
            )
            written += 1
        except Exception:
            logger.exception("Usage snapshot failed tenant=%s", tenant_id)
    return written


def expiring_within(days: int, now: datetime | None = None) -> datetime:
    return (now or _now()) + timedelta(days=days)
