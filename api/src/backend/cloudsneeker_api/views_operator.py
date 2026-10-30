"""Operator console API (``/api/v1/operator/*``) and tenant ``/entitlements``.

The operator API is for the people who run the platform, not for customers:

* Access needs an active ``PlatformOperator`` row for the signed-in user.
  Tenant roles (even tenant administrators) are irrelevant, and API keys are
  refused. Everyone else gets 404, so the console does not advertise itself.
* ``CLOUDSNEEKER_OPERATOR_ENABLED=false`` turns the whole API off (404).
* Reads are open to every operator role; subscription and plan changes need
  ``owner`` or ``billing``; suspending or cancelling a tenant and listing the
  operators need ``owner``.
* Every change writes an ``OperatorAuditEvent`` (field names, never values)
  and, for subscriptions, a ``SubscriptionEvent`` plus an entry in the
  customer's own audit log.

Operator tables are not row-level security protected and are always read
through ``MainRouter.admin_db``.
"""

from __future__ import annotations

import logging
import math
import os
from datetime import timedelta
from uuid import UUID

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX
from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.serializers_operator import (
    PlanWriteSerializer,
    SubscriptionUpdateSerializer,
)
from cloudsneeker_api.services import entitlements as service
from cloudsneeker_api.services import plan_catalog as catalog
from cloudsneeker_api.views import JSONAPIDocumentRenderer
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import permissions, status
from rest_framework.exceptions import (
    APIException,
    NotFound,
    PermissionDenied,
    ValidationError,
)
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)

OPERATOR_ENABLED_ENV = "CLOUDSNEEKER_OPERATOR_ENABLED"
OPERATOR_TAG = "Operator console"

READ_ROLES = frozenset(
    {
        catalog.OPERATOR_ROLE_OWNER,
        catalog.OPERATOR_ROLE_SUPPORT,
        catalog.OPERATOR_ROLE_BILLING,
        catalog.OPERATOR_ROLE_READ_ONLY,
    }
)
BILLING_ROLES = frozenset({catalog.OPERATOR_ROLE_OWNER, catalog.OPERATOR_ROLE_BILLING})
OWNER_ROLES = frozenset({catalog.OPERATOR_ROLE_OWNER})
# Statuses only an owner may set.
OWNER_ONLY_STATUSES = frozenset({catalog.STATUS_SUSPENDED, catalog.STATUS_CANCELLED})

DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100
HISTORY_LIMIT = 50
RECENT_SCANS_LIMIT = 10
MEMBERS_LIMIT = 200
DEFAULT_USAGE_DAYS = 30
MAX_USAGE_DAYS = 400

TYPE_ENTITLEMENTS = f"{JSON_API_TYPE_PREFIX}entitlements"
TYPE_OPERATOR = f"{JSON_API_TYPE_PREFIX}platform-operators"
TYPE_TENANT = f"{JSON_API_TYPE_PREFIX}operator-tenants"
TYPE_SUBSCRIPTION = f"{JSON_API_TYPE_PREFIX}subscriptions"
TYPE_SUBSCRIPTION_EVENT = f"{JSON_API_TYPE_PREFIX}subscription-events"
TYPE_PLAN = f"{JSON_API_TYPE_PREFIX}plans"
TYPE_USAGE = f"{JSON_API_TYPE_PREFIX}usage-snapshots"
TYPE_OPERATOR_AUDIT = f"{JSON_API_TYPE_PREFIX}operator-audit-events"

# Role -> what the console lets that role do (sent to the UI by ``/me``).
ROLE_CAPABILITIES = {
    catalog.OPERATOR_ROLE_OWNER: [
        "view",
        "manage_subscriptions",
        "suspend_tenants",
        "manage_plans",
        "view_operators",
    ],
    catalog.OPERATOR_ROLE_BILLING: ["view", "manage_subscriptions", "manage_plans"],
    catalog.OPERATOR_ROLE_SUPPORT: ["view"],
    catalog.OPERATOR_ROLE_READ_ONLY: ["view"],
}


class Conflict(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "The request conflicts with the current state."
    default_code = "conflict"


def operator_enabled() -> bool:
    """``CLOUDSNEEKER_OPERATOR_ENABLED`` (default true)."""
    value = (os.environ.get(OPERATOR_ENABLED_ENV) or "true").strip().lower()
    return value not in ("0", "false", "no", "off")


def _admin_db() -> str:
    from api.db_router import MainRouter

    return MainRouter.admin_db


def active_operator(user):
    """The active ``PlatformOperator`` row of ``user``, or ``None``."""
    from cloudsneeker_api.models import PlatformOperator

    if not getattr(user, "is_authenticated", False):
        return None
    return (
        PlatformOperator.objects.using(_admin_db())
        .filter(user_id=user.id, active=True)
        .first()
    )


def _is_api_key(auth) -> bool:
    return bool(hasattr(auth, "get") and auth.get("api_key_prefix"))


class IsPlatformOperator(permissions.BasePermission):
    """Signed-in user with an active operator role allowed for the method."""

    def has_permission(self, request, view):
        if not operator_enabled():
            raise NotFound()
        if not getattr(request.user, "is_authenticated", False):
            return False
        if _is_api_key(request.auth):
            raise NotFound()
        operator = active_operator(request.user)
        if operator is None:
            raise NotFound()
        request.platform_operator = operator
        allowed = view.roles_for(request.method)
        if operator.role not in allowed:
            raise PermissionDenied("Your operator role cannot do this.")
        return True


# --- Documents ------------------------------------------------------------------


def resource(resource_type: str, resource_id, attributes: dict) -> dict:
    return {"type": resource_type, "id": str(resource_id), "attributes": attributes}


def _iso(value):
    return value.isoformat() if value else None


def _page_params(request) -> tuple[int, int]:
    def number(name: str, default: int) -> int:
        try:
            return max(1, int(request.query_params.get(name, default)))
        except (TypeError, ValueError):
            return default

    size = min(MAX_PAGE_SIZE, number("page[size]", DEFAULT_PAGE_SIZE))
    return number("page[number]", 1), size


def paginate(request, items: list) -> tuple[list, dict]:
    page, size = _page_params(request)
    count = len(items)
    pages = max(1, math.ceil(count / size)) if size else 1
    start = (page - 1) * size
    return items[start : start + size], {
        "pagination": {"page": page, "pages": pages, "count": count}
    }


def _filter_param(request, name: str) -> str:
    value = request.query_params.get(f"filter[{name}]")
    if value is None:
        value = request.query_params.get(name, "")
    return str(value or "").strip()


def plan_attributes(plan, subscriber_count: int | None = None) -> dict:
    attributes = {
        "code": plan.code,
        "name": plan.name,
        "description": plan.description,
        "features": catalog.clean_features(plan.features),
        "limits": service.effective_limits(plan.limits, None),
        "is_public": plan.is_public,
        "sort_order": plan.sort_order,
        "inserted_at": _iso(plan.inserted_at),
        "updated_at": _iso(plan.updated_at),
    }
    if subscriber_count is not None:
        attributes["subscriber_count"] = subscriber_count
    return attributes


def subscription_attributes(subscription, entitlements) -> dict:
    return {
        "tenant_id": str(subscription.tenant_id),
        "plan": subscription.plan.code,
        "plan_name": subscription.plan.name,
        "status": subscription.status,
        "effective_status": entitlements.effective_status,
        "read_only": entitlements.read_only,
        "starts_at": _iso(subscription.starts_at),
        "ends_at": _iso(subscription.ends_at),
        "trial_ends_at": _iso(subscription.trial_ends_at),
        "seats": subscription.seats,
        "feature_overrides": subscription.feature_overrides or {},
        "limit_overrides": subscription.limit_overrides or {},
        "billing_source": subscription.billing_source,
        "external_customer_id": subscription.external_customer_id,
        "notes": subscription.notes,
        "features": entitlements.features,
        "limits": entitlements.limits,
        "updated_at": _iso(subscription.updated_at),
    }


def event_attributes(event) -> dict:
    return {
        "tenant_id": str(event.tenant_id),
        "action": event.action,
        "source": event.source,
        "changes": event.changes or {},
        "actor_id": str(event.actor_id) if event.actor_id else None,
        "actor_email": event.actor_email,
        "inserted_at": _iso(event.inserted_at),
    }


def entitlements_attributes(entitlements, usage: dict | None) -> dict:
    data = entitlements.as_dict()
    data.pop("tenant_id", None)
    data.pop("fallback", None)
    data.pop("subscription_id", None)
    data["plan"] = {"code": data.pop("plan_code"), "name": data.pop("plan_name")}
    data["usage"] = usage or {}
    data["over_limit"] = service.over_limit_keys(usage or {}, entitlements.limits)
    return data


# --- Operator audit ---------------------------------------------------------------


def record_operator_event(
    request,
    action: str,
    *,
    tenant_id=None,
    target_type: str = "",
    target_id: str = "",
    changed_fields: list[str] | None = None,
    metadata: dict | None = None,
):
    """Write one ``OperatorAuditEvent``; never raises."""
    try:
        from cloudsneeker_api.audit import client_ip, request_id
        from cloudsneeker_api.models import OperatorAuditEvent

        operator = getattr(request, "platform_operator", None)
        user = request.user
        django_request = getattr(request, "_request", request)
        return OperatorAuditEvent.objects.using(_admin_db()).create(
            actor_id=getattr(user, "id", None),
            actor_email=(getattr(user, "email", "") or "")[:254],
            actor_role=getattr(operator, "role", "") or "",
            action=action[:100],
            tenant_id=tenant_id,
            target_type=target_type[:64],
            target_id=str(target_id or "")[:255],
            changed_fields=list(changed_fields or []),
            metadata=metadata or {},
            ip_address=client_ip(django_request),
            user_agent=(django_request.META.get("HTTP_USER_AGENT", "") or "")[:512],
            request_id=request_id()[:64],
        )
    except Exception:
        logger.exception("Operator audit event not recorded action=%s", action)
        return None


def _record_customer_audit(request, tenant_id, changed: list[str]) -> None:
    """Show the operator change in the customer's own audit log."""
    from cloudsneeker_api.audit import record_event

    record_event(
        str(tenant_id),
        "operator.subscription_update",
        request=request,
        target_type="subscription",
        target_id=str(tenant_id),
        status_code=200,
        metadata={"fields": changed, "operator": True},
    )


# --- Base view ---------------------------------------------------------------------


class OperatorAPIView(APIView):
    """JWT-authenticated, operator-only, hand-built JSON:API documents."""

    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
    permission_classes = [IsPlatformOperator]
    renderer_classes = [JSONAPIDocumentRenderer]
    parser_classes = [LenientJSONAPIParser, JSONParser]
    read_roles = READ_ROLES
    write_roles = BILLING_ROLES

    def roles_for(self, method: str) -> frozenset:
        if method in ("GET", "HEAD", "OPTIONS"):
            return self.read_roles
        return self.write_roles

    def handle_exception(self, exc):
        response = super().handle_exception(exc)
        data = getattr(response, "data", None)
        if isinstance(data, dict) and "errors" not in data:
            code = getattr(exc, "default_code", "error")
            detail = data.get("detail", data)
            if isinstance(exc, ValidationError) and not isinstance(detail, str):
                detail = (
                    "; ".join(
                        f"{key}: {value[0] if isinstance(value, list) else value}"
                        for key, value in (
                            detail.items() if isinstance(detail, dict) else []
                        )
                    )
                    or "Invalid request."
                )
            response.data = {
                "errors": [
                    {
                        "status": str(response.status_code),
                        "code": str(getattr(detail, "code", code) or code),
                        "detail": str(detail),
                    }
                ]
            }
        elif isinstance(data, list):
            response.data = {
                "errors": [
                    {"status": str(response.status_code), "detail": str(item)}
                    for item in data
                ]
            }
        return response

    @staticmethod
    def body(request) -> dict:
        data = request.data
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            inner = data["data"]
            data = inner.get("attributes", inner)
        return dict(data) if isinstance(data, dict) else {}


def _tenant_or_404(tenant_id):
    from api.models import Tenant

    tenant = Tenant.objects.using(_admin_db()).filter(id=tenant_id).first()
    if tenant is None:
        raise NotFound("Tenant not found.")
    return tenant


# --- /operator/me ------------------------------------------------------------------


@extend_schema(
    tags=[OPERATOR_TAG],
    summary="Current platform operator",
    description="The signed-in user's operator role; 404 for everyone else.",
    responses={
        200: OpenApiResponse(description="Operator role and capabilities"),
        404: OpenApiResponse(description="Not an operator"),
    },
)
class OperatorMeView(OperatorAPIView):
    def get(self, request):
        operator = request.platform_operator
        return Response(
            {
                "data": resource(
                    TYPE_OPERATOR,
                    operator.id,
                    {
                        "email": request.user.email,
                        "name": getattr(request.user, "name", ""),
                        "role": operator.role,
                        "capabilities": ROLE_CAPABILITIES.get(operator.role, []),
                    },
                )
            }
        )


# --- Tenants -----------------------------------------------------------------------


def _all_tenant_rows():
    """Every tenant with its subscription, entitlements, usage and activity."""
    from api.models import Membership, Tenant
    from cloudsneeker_api.models import Subscription
    from django.db.models import Count

    alias = _admin_db()
    tenants = list(Tenant.objects.using(alias).order_by("name"))
    tenant_ids = [tenant.id for tenant in tenants]
    subscriptions = {
        sub.tenant_id: sub
        for sub in Subscription.objects.using(alias)
        .select_related("plan")
        .filter(tenant_id__in=tenant_ids)
    }
    usage = service.usage_by_tenant(tenant_ids)
    activity = service.last_activity_by_tenant(tenant_ids)
    member_counts = {
        row["tenant_id"]: row["total"]
        for row in Membership.objects.using(alias)
        .filter(tenant_id__in=tenant_ids)
        .values("tenant_id")
        .annotate(total=Count("id"))
        .order_by()
    }
    rows = []
    for tenant in tenants:
        subscription = subscriptions.get(tenant.id)
        if subscription is None:
            subscription = service.ensure_subscription(str(tenant.id))
        entitlements = service.build_entitlements(
            str(tenant.id), subscription, subscription.plan
        )
        tenant_usage = usage.get(str(tenant.id), {})
        rows.append(
            {
                "tenant": tenant,
                "subscription": subscription,
                "entitlements": entitlements,
                "usage": tenant_usage,
                "over_limit": service.over_limit_keys(
                    tenant_usage, entitlements.limits
                ),
                "member_count": member_counts.get(tenant.id, 0),
                "last_activity": activity.get(str(tenant.id)),
            }
        )
    return rows


def tenant_attributes(row: dict) -> dict:
    tenant = row["tenant"]
    entitlements = row["entitlements"]
    subscription = row["subscription"]
    return {
        "name": tenant.name,
        "inserted_at": _iso(tenant.inserted_at),
        "plan": entitlements.plan_code,
        "plan_name": entitlements.plan_name,
        "status": subscription.status,
        "effective_status": entitlements.effective_status,
        "read_only": entitlements.read_only,
        "starts_at": entitlements.starts_at,
        "ends_at": entitlements.ends_at,
        "trial_ends_at": entitlements.trial_ends_at,
        "billing_source": subscription.billing_source,
        "member_count": row["member_count"],
        "last_activity": row["last_activity"],
        "usage": row["usage"],
        "limits": entitlements.limits,
        "features": entitlements.features,
        "over_limit": row["over_limit"],
    }


def _expires_within(row: dict, days: int) -> bool:
    from django.utils import timezone

    subscription = row["subscription"]
    end = subscription.ends_at
    if subscription.status == catalog.STATUS_TRIAL and subscription.trial_ends_at:
        end = min(filter(None, [end, subscription.trial_ends_at]))
    if end is None:
        return False
    now = timezone.now()
    return now <= end <= now + timedelta(days=days)


def filter_tenant_rows(request, rows: list[dict]) -> list[dict]:
    search = _filter_param(request, "search").lower()
    status_filter = _filter_param(request, "status")
    plan_filter = _filter_param(request, "plan")
    expiring = _filter_param(request, "expiring_within_days")
    over_limit = _filter_param(request, "over_limit").lower()

    if search:
        rows = [
            row
            for row in rows
            if search in row["tenant"].name.lower()
            or search in str(row["tenant"].id)
            or search in (row["subscription"].external_customer_id or "").lower()
        ]
    if status_filter:
        wanted = {value for value in status_filter.split(",") if value}
        rows = [row for row in rows if row["entitlements"].effective_status in wanted]
    if plan_filter:
        wanted = {value for value in plan_filter.split(",") if value}
        rows = [row for row in rows if row["entitlements"].plan_code in wanted]
    if expiring:
        try:
            days = max(0, int(expiring))
        except ValueError:
            raise ValidationError("'expiring_within_days' must be a number.") from None
        rows = [row for row in rows if _expires_within(row, days)]
    if over_limit in ("true", "1", "yes"):
        rows = [row for row in rows if row["over_limit"]]
    return rows


SORT_KEYS = {
    "name": lambda row: row["tenant"].name.lower(),
    "inserted_at": lambda row: row["tenant"].inserted_at,
    "ends_at": lambda row: row["entitlements"].ends_at or "9999",
    "last_activity": lambda row: row["last_activity"] or "",
    "plan": lambda row: row["entitlements"].plan_code,
    "status": lambda row: row["entitlements"].effective_status,
}


def sort_tenant_rows(request, rows: list[dict]) -> list[dict]:
    sort = request.query_params.get("sort", "name") or "name"
    reverse = sort.startswith("-")
    key = SORT_KEYS.get(sort.lstrip("-"))
    if key is None:
        raise ValidationError("Unknown sort field.")
    return sorted(rows, key=key, reverse=reverse)


def tenants_summary(rows: list[dict]) -> dict:
    """Counts for the overview: by status, by plan, expiring, over limit."""
    by_status: dict[str, int] = {}
    by_plan: dict[str, int] = {}
    for row in rows:
        entitlements = row["entitlements"]
        by_status[entitlements.effective_status] = (
            by_status.get(entitlements.effective_status, 0) + 1
        )
        by_plan[entitlements.plan_code] = by_plan.get(entitlements.plan_code, 0) + 1
    return {
        "total": len(rows),
        "by_status": by_status,
        "by_plan": by_plan,
        "expiring_within_30_days": sum(1 for row in rows if _expires_within(row, 30)),
        "over_limit": sum(1 for row in rows if row["over_limit"]),
    }


@extend_schema(
    tags=[OPERATOR_TAG],
    summary="List customer tenants",
    description=(
        "Every tenant with plan, status, end date, usage against limits, "
        "member count and last activity. Filters: `filter[search]`, "
        "`filter[status]`, `filter[plan]`, `filter[expiring_within_days]`, "
        "`filter[over_limit]`. `sort`: name, inserted_at, ends_at, "
        "last_activity, plan, status (prefix `-` for descending). "
        "`meta.summary` counts all tenants by status and plan."
    ),
    responses={200: OpenApiResponse(description="Tenants")},
)
class OperatorTenantListView(OperatorAPIView):
    def get(self, request):
        all_rows = _all_tenant_rows()
        rows = sort_tenant_rows(request, filter_tenant_rows(request, all_rows))
        page, meta = paginate(request, rows)
        meta["summary"] = tenants_summary(all_rows)
        return Response(
            {
                "data": [
                    resource(TYPE_TENANT, row["tenant"].id, tenant_attributes(row))
                    for row in page
                ],
                "meta": meta,
            }
        )


@extend_schema(
    tags=[OPERATOR_TAG],
    summary="Get a customer tenant",
    description=(
        "Subscription, effective entitlements, usage against limits, members, "
        "recent scans and subscription history of one tenant."
    ),
    responses={
        200: OpenApiResponse(description="Tenant detail"),
        404: OpenApiResponse(description="Unknown tenant"),
    },
)
class OperatorTenantDetailView(OperatorAPIView):
    def get(self, request, tenant_id):
        from api.models import Membership, Scan
        from cloudsneeker_api.models import SubscriptionEvent

        alias = _admin_db()
        tenant = _tenant_or_404(tenant_id)
        subscription = service.ensure_subscription(str(tenant.id))
        entitlements = service.build_entitlements(
            str(tenant.id), subscription, subscription.plan
        )
        usage = service.usage_for_tenant(str(tenant.id))
        members = [
            {
                "user_id": str(membership.user_id),
                "email": membership.user.email,
                "name": membership.user.name,
                "role": membership.role,
                "date_joined": _iso(membership.date_joined),
                "last_login": _iso(membership.user.last_login),
            }
            for membership in Membership.objects.using(alias)
            .select_related("user")
            .filter(tenant_id=tenant.id)
            .order_by("date_joined")[:MEMBERS_LIMIT]
        ]
        scans = [
            {
                "id": str(scan.id),
                "name": scan.name,
                "state": scan.state,
                "trigger": scan.trigger,
                "inserted_at": _iso(scan.inserted_at),
                "completed_at": _iso(scan.completed_at),
            }
            for scan in Scan.all_objects.using(alias)
            .filter(tenant_id=tenant.id)
            .order_by("-inserted_at")[:RECENT_SCANS_LIMIT]
        ]
        history = [
            resource(TYPE_SUBSCRIPTION_EVENT, event.id, event_attributes(event))
            for event in SubscriptionEvent.objects.using(alias)
            .filter(tenant_id=tenant.id)
            .order_by("-inserted_at")[:HISTORY_LIMIT]
        ]
        row = {
            "tenant": tenant,
            "subscription": subscription,
            "entitlements": entitlements,
            "usage": usage,
            "over_limit": service.over_limit_keys(usage, entitlements.limits),
            "member_count": len(members),
            "last_activity": service.last_activity_by_tenant([tenant.id]).get(
                str(tenant.id)
            ),
        }
        attributes = tenant_attributes(row)
        attributes.update(
            {
                "subscription": subscription_attributes(subscription, entitlements),
                "members": members,
                "recent_scans": scans,
                "history": history,
            }
        )
        return Response({"data": resource(TYPE_TENANT, tenant.id, attributes)})


@extend_schema(
    tags=[OPERATOR_TAG],
    summary="Daily usage snapshots of a tenant",
    description="Newest first; `filter[days]` (default 30).",
    responses={200: OpenApiResponse(description="Usage snapshots")},
)
class OperatorTenantUsageView(OperatorAPIView):
    def get(self, request, tenant_id):
        from cloudsneeker_api.models import UsageSnapshot
        from django.utils import timezone

        tenant = _tenant_or_404(tenant_id)
        try:
            days = int(_filter_param(request, "days") or DEFAULT_USAGE_DAYS)
        except ValueError:
            raise ValidationError("'days' must be a number.") from None
        days = max(1, min(MAX_USAGE_DAYS, days))
        since = timezone.now().date() - timedelta(days=days)
        snapshots = (
            UsageSnapshot.objects.using(_admin_db())
            .filter(tenant_id=tenant.id, date__gte=since)
            .order_by("-date")
        )
        return Response(
            {
                "data": [
                    resource(
                        TYPE_USAGE,
                        snapshot.id,
                        {
                            "tenant_id": str(snapshot.tenant_id),
                            "date": snapshot.date.isoformat(),
                            "counts": snapshot.counts or {},
                        },
                    )
                    for snapshot in snapshots
                ]
            }
        )


# --- Subscriptions -------------------------------------------------------------------


@extend_schema(
    tags=[OPERATOR_TAG],
    summary="Get a tenant subscription",
    responses={200: OpenApiResponse(description="Subscription")},
)
class OperatorSubscriptionView(OperatorAPIView):
    def get(self, request, tenant_id):
        tenant = _tenant_or_404(tenant_id)
        subscription = service.ensure_subscription(str(tenant.id))
        entitlements = service.build_entitlements(
            str(tenant.id), subscription, subscription.plan
        )
        return Response(
            {
                "data": resource(
                    TYPE_SUBSCRIPTION,
                    subscription.id,
                    subscription_attributes(subscription, entitlements),
                )
            }
        )

    @extend_schema(
        tags=[OPERATOR_TAG],
        summary="Change a tenant subscription",
        description=(
            "Plan, status, dates, seats, feature toggles and limit overrides. "
            "Writes the subscription history and the operator audit log. "
            "Setting `suspended` or `cancelled` needs the owner role."
        ),
        request=SubscriptionUpdateSerializer,
        responses={
            200: OpenApiResponse(description="Updated subscription"),
            400: OpenApiResponse(description="Invalid change"),
            403: OpenApiResponse(description="Role not allowed"),
        },
    )
    def patch(self, request, tenant_id):
        tenant = _tenant_or_404(tenant_id)
        data = self.body(request)
        new_status = data.get("status")
        if (
            new_status in OWNER_ONLY_STATUSES
            and request.platform_operator.role not in OWNER_ROLES
        ):
            raise PermissionDenied("Only an owner can suspend or cancel a tenant.")
        try:
            subscription, changed = service.update_subscription(
                str(tenant.id),
                data,
                actor_id=str(request.user.id),
                actor_email=request.user.email,
            )
        except service.SubscriptionError as error:
            raise ValidationError(str(error)) from None
        if changed:
            record_operator_event(
                request,
                "subscription.update",
                tenant_id=tenant.id,
                target_type="subscription",
                target_id=str(subscription.id),
                changed_fields=changed,
                metadata={"tenant_name": tenant.name},
            )
            _record_customer_audit(request, tenant.id, changed)
        subscription.refresh_from_db(using=_admin_db())
        entitlements = service.build_entitlements(
            str(tenant.id), subscription, subscription.plan
        )
        return Response(
            {
                "data": resource(
                    TYPE_SUBSCRIPTION,
                    subscription.id,
                    subscription_attributes(subscription, entitlements),
                ),
                "meta": {"changed": changed},
            }
        )


# --- Plans -------------------------------------------------------------------------


def _subscriber_counts() -> dict:
    from cloudsneeker_api.models import Subscription
    from django.db.models import Count

    return {
        row["plan_id"]: row["total"]
        for row in Subscription.objects.using(_admin_db())
        .values("plan_id")
        .annotate(total=Count("id"))
        .order_by()
    }


def _validated_plan(request, data: dict, partial: bool) -> dict:
    serializer = PlanWriteSerializer(data=data, partial=partial)
    serializer.is_valid(raise_exception=True)
    values = dict(serializer.validated_data)
    if not partial:
        missing = [name for name in ("code", "name") if not values.get(name)]
        if missing:
            raise ValidationError(f"Required: {', '.join(missing)}.")
    return values


@extend_schema(
    tags=[OPERATOR_TAG],
    summary="List plans",
    responses={200: OpenApiResponse(description="Plans in catalogue order")},
)
class OperatorPlanListView(OperatorAPIView):
    def get(self, request):
        from cloudsneeker_api.models import Plan

        counts = _subscriber_counts()
        return Response(
            {
                "data": [
                    resource(
                        TYPE_PLAN,
                        plan.code,
                        plan_attributes(plan, counts.get(plan.id, 0)),
                    )
                    for plan in Plan.objects.using(_admin_db()).order_by(
                        "sort_order", "code"
                    )
                ],
                "meta": {
                    "feature_keys": list(catalog.FEATURE_KEYS),
                    "limit_keys": list(catalog.LIMIT_KEYS),
                },
            }
        )

    @extend_schema(
        tags=[OPERATOR_TAG],
        summary="Create a plan",
        request=PlanWriteSerializer,
        responses={
            201: OpenApiResponse(description="Created plan"),
            409: OpenApiResponse(description="Code already used"),
        },
    )
    def post(self, request):
        from cloudsneeker_api.models import Plan

        values = _validated_plan(request, self.body(request), partial=False)
        alias = _admin_db()
        if Plan.objects.using(alias).filter(code=values["code"]).exists():
            raise Conflict("A plan with this code already exists.")
        plan = Plan.objects.using(alias).create(**values)
        record_operator_event(
            request,
            "plan.create",
            target_type="plan",
            target_id=plan.code,
            changed_fields=sorted(values),
        )
        return Response(
            {"data": resource(TYPE_PLAN, plan.code, plan_attributes(plan, 0))},
            status=status.HTTP_201_CREATED,
        )


@extend_schema(
    tags=[OPERATOR_TAG],
    summary="Get a plan",
    responses={200: OpenApiResponse(description="Plan")},
)
class OperatorPlanDetailView(OperatorAPIView):
    def _plan(self, code):
        from cloudsneeker_api.models import Plan

        plan = Plan.objects.using(_admin_db()).filter(code=code).first()
        if plan is None:
            raise NotFound("Plan not found.")
        return plan

    def get(self, request, code):
        plan = self._plan(code)
        return Response(
            {
                "data": resource(
                    TYPE_PLAN,
                    plan.code,
                    plan_attributes(plan, _subscriber_counts().get(plan.id, 0)),
                )
            }
        )

    @extend_schema(
        tags=[OPERATOR_TAG],
        summary="Change a plan",
        description="Applies to every tenant on the plan. The code cannot change.",
        request=PlanWriteSerializer,
        responses={200: OpenApiResponse(description="Updated plan")},
    )
    def patch(self, request, code):
        plan = self._plan(code)
        values = _validated_plan(request, self.body(request), partial=True)
        if "code" in values and values["code"] != plan.code:
            raise ValidationError("A plan code cannot be changed.")
        values.pop("code", None)
        changed = []
        for name, value in values.items():
            if getattr(plan, name) != value:
                setattr(plan, name, value)
                changed.append(name)
        if changed:
            plan.save(using=_admin_db())
            service.invalidate()
            record_operator_event(
                request,
                "plan.update",
                target_type="plan",
                target_id=plan.code,
                changed_fields=sorted(changed),
            )
        return Response(
            {
                "data": resource(
                    TYPE_PLAN,
                    plan.code,
                    plan_attributes(plan, _subscriber_counts().get(plan.id, 0)),
                ),
                "meta": {"changed": sorted(changed)},
            }
        )

    @extend_schema(
        tags=[OPERATOR_TAG],
        summary="Delete a plan",
        description="Only a plan no tenant uses; the legacy plan stays.",
        responses={
            204: OpenApiResponse(description="Deleted"),
            409: OpenApiResponse(description="Plan in use or protected"),
        },
    )
    def delete(self, request, code):
        plan = self._plan(code)
        if plan.code in (catalog.LEGACY_PLAN_CODE, catalog.default_plan_code()):
            raise Conflict("The legacy and default plans cannot be deleted.")
        if _subscriber_counts().get(plan.id, 0):
            raise Conflict("Move its tenants to another plan first.")
        plan.delete(using=_admin_db())
        service.invalidate()
        record_operator_event(
            request, "plan.delete", target_type="plan", target_id=code
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Operators and audit -----------------------------------------------------------


@extend_schema(
    tags=[OPERATOR_TAG],
    summary="List platform operators",
    description="Owner only. Grant and revoke with the `cloudsneeker_operator` command.",
    responses={200: OpenApiResponse(description="Operators")},
)
class OperatorListView(OperatorAPIView):
    read_roles = OWNER_ROLES

    def get(self, request):
        from cloudsneeker_api.models import PlatformOperator

        operators = (
            PlatformOperator.objects.using(_admin_db())
            .select_related("user")
            .order_by("-active", "user__email")
        )
        return Response(
            {
                "data": [
                    resource(
                        TYPE_OPERATOR,
                        operator.id,
                        {
                            "email": operator.user.email,
                            "name": operator.user.name,
                            "role": operator.role,
                            "active": operator.active,
                            "granted_by": operator.granted_by,
                            "inserted_at": _iso(operator.inserted_at),
                            "updated_at": _iso(operator.updated_at),
                        },
                    )
                    for operator in operators
                ]
            }
        )


@extend_schema(
    tags=[OPERATOR_TAG],
    summary="List operator audit events",
    description=(
        "Newest first. Filters: `filter[tenant]`, `filter[action]` (prefix), "
        "`filter[actor]` (email contains). Paginated with `page[number]` and "
        "`page[size]`."
    ),
    responses={200: OpenApiResponse(description="Operator audit events")},
)
class OperatorAuditListView(OperatorAPIView):
    def get(self, request):
        from cloudsneeker_api.models import OperatorAuditEvent

        queryset = OperatorAuditEvent.objects.using(_admin_db()).order_by(
            "-inserted_at"
        )
        tenant = _filter_param(request, "tenant")
        if tenant:
            try:
                queryset = queryset.filter(tenant_id=UUID(tenant))
            except ValueError:
                raise ValidationError("'tenant' must be a tenant id.") from None
        action = _filter_param(request, "action")
        if action:
            queryset = queryset.filter(action__startswith=action)
        actor = _filter_param(request, "actor")
        if actor:
            queryset = queryset.filter(actor_email__icontains=actor)
        page, size = _page_params(request)
        count = queryset.count()
        events = queryset[(page - 1) * size : page * size]
        return Response(
            {
                "data": [
                    resource(
                        TYPE_OPERATOR_AUDIT,
                        event.id,
                        {
                            "inserted_at": _iso(event.inserted_at),
                            "actor_id": str(event.actor_id) if event.actor_id else None,
                            "actor_email": event.actor_email,
                            "actor_role": event.actor_role,
                            "action": event.action,
                            "tenant_id": str(event.tenant_id)
                            if event.tenant_id
                            else None,
                            "target_type": event.target_type,
                            "target_id": event.target_id,
                            "changed_fields": event.changed_fields or [],
                            "metadata": event.metadata or {},
                            "ip_address": event.ip_address,
                        },
                    )
                    for event in events
                ],
                "meta": {
                    "pagination": {
                        "page": page,
                        "pages": max(1, math.ceil(count / size)),
                        "count": count,
                    }
                },
            }
        )


# --- Tenant entitlements -------------------------------------------------------------


@extend_schema(
    tags=["Cloudsneeker"],
    summary="Plan entitlements of the current organization",
    description=(
        "Plan, subscription status, enabled features, limits, current usage "
        "and the read-only flag of the tenant in the token. The web app uses "
        "it to hide features outside the plan and to show renewal banners."
    ),
    responses={
        200: OpenApiResponse(description="Entitlements"),
        401: OpenApiResponse(description="Not signed in"),
    },
)
class EntitlementsView(APIView):
    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    renderer_classes = [JSONAPIDocumentRenderer]

    def get(self, request):
        auth = request.auth
        tenant_id = auth.get("tenant_id") if hasattr(auth, "get") else None
        if not tenant_id:
            raise NotFound("No organization in this session.")
        try:
            entitlements = service.for_tenant(str(tenant_id))
            usage = service.usage_for_tenant(str(tenant_id))
        except Exception:
            logger.exception("Entitlements lookup failed tenant=%s", tenant_id)
            entitlements = service.fallback_entitlements(str(tenant_id))
            usage = {}
        return Response(
            {
                "data": resource(
                    TYPE_ENTITLEMENTS,
                    tenant_id,
                    entitlements_attributes(entitlements, usage),
                )
            }
        )
