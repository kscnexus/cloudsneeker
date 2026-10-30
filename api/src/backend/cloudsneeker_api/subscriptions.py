"""Plan enforcement for every ``/api/v1/`` request (operator console, Phase 1).

``SubscriptionEnforcementMiddleware`` runs before the view so upstream views
stay untouched. It reads only headers (never the body, which upstream views
read from ``request.stream``), decides with the tenant's cached entitlements,
and answers with a JSON:API 403 for:

* ``subscription_inactive``: a write while the subscription is suspended,
  expired or cancelled (sign-in, token refresh and switch, entitlements,
  the user's own profile and password, and the operator API stay open);
* ``feature_not_in_plan``: a path that belongs to a feature the plan lacks;
* ``plan_limit_reached``: creating a provider, invitation, application
  security target or report schedule at the plan limit.

Anything unexpected (bad token, missing tables, database errors) is logged
and the request continues: the view still authenticates and authorizes.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from cloudsneeker_api.services import plan_catalog as catalog
from django.http import JsonResponse

logger = logging.getLogger(__name__)

API_PREFIX = "/api/v1/"
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
JSONAPI_CONTENT_TYPE = "application/vnd.api+json"

CODE_SUBSCRIPTION_INACTIVE = "subscription_inactive"
CODE_FEATURE_NOT_IN_PLAN = "feature_not_in_plan"
CODE_PLAN_LIMIT_REACHED = "plan_limit_reached"

# Paths (after ``/api/v1/``) never refused by this middleware.
EXEMPT_PREFIXES = ("operator/", "operator", "schema", "docs")
# Writes still allowed while the subscription is inactive.
READ_ONLY_ALLOWED_PATHS = frozenset(
    {
        "tokens",
        "tokens/refresh",
        "tokens/switch",
        "tokens/saml",
        "tokens/google",
        "tokens/github",
        "entitlements",
        "invitations/accept",
        "users/me",
    }
)
READ_ONLY_ALLOWED_PREFIXES = ("auth/", "accounts/")

# Path prefix (after ``/api/v1/``) -> feature key. First match wins, so
# longer prefixes come first.
FEATURE_PATH_PREFIXES: tuple[tuple[str, str], ...] = (
    ("report-schedules", catalog.FEATURE_REPORT_SCHEDULES),
    ("report-", catalog.FEATURE_REPORTS),
    ("trivy-", catalog.FEATURE_APPLICATION_SECURITY),
    ("custodian-", catalog.FEATURE_GOVERNANCE),
    ("attack-paths", catalog.FEATURE_ATTACK_PATHS),
    ("compliance-overviews", catalog.FEATURE_COMPLIANCE),
    ("lighthouse", catalog.FEATURE_SEEKER_AI),
    ("finding-triages", catalog.FEATURE_FINDING_TRIAGE),
    ("audit-events", catalog.FEATURE_AUDIT_LOG),
    ("integrations", catalog.FEATURE_INTEGRATIONS),
    ("saml-config", catalog.FEATURE_SSO),
    ("api-keys", catalog.FEATURE_API_ACCESS),
)
# ``findings/<uid>/triage...`` (the finding UID may contain ``/``).
FINDING_TRIAGE_PATH = re.compile(r"^findings/.+/triage(/.*)?$")

# Collection path (POST creates) -> (limit key, usage key).
LIMITED_COLLECTIONS = {
    "providers": (catalog.LIMIT_PROVIDERS, "providers"),
    "tenants/invitations": (catalog.LIMIT_USERS, "users"),
    "trivy-targets": (
        catalog.LIMIT_APPLICATION_SECURITY_TARGETS,
        "application_security_targets",
    ),
    "report-schedules": (catalog.LIMIT_REPORT_SCHEDULES, "report_schedules"),
}

FEATURE_LABELS = {
    catalog.FEATURE_CLOUD_POSTURE: "Cloud posture",
    catalog.FEATURE_ATTACK_PATHS: "Attack paths",
    catalog.FEATURE_COMPLIANCE: "Compliance",
    catalog.FEATURE_APPLICATION_SECURITY: "Application security",
    catalog.FEATURE_SAST: "Static code analysis",
    catalog.FEATURE_GOVERNANCE: "Governance",
    catalog.FEATURE_REPORTS: "Reports",
    catalog.FEATURE_REPORT_SCHEDULES: "Scheduled reports",
    catalog.FEATURE_SEEKER_AI: "Assistant",
    catalog.FEATURE_FINDING_TRIAGE: "Finding triage",
    catalog.FEATURE_AUDIT_LOG: "Audit log",
    catalog.FEATURE_SSO: "Single sign-on",
    catalog.FEATURE_API_ACCESS: "API access",
    catalog.FEATURE_INTEGRATIONS: "Integrations",
}
LIMIT_LABELS = {
    catalog.LIMIT_PROVIDERS: "providers",
    catalog.LIMIT_USERS: "users",
    catalog.LIMIT_APPLICATION_SECURITY_TARGETS: "application security targets",
    catalog.LIMIT_REPORT_SCHEDULES: "report schedules",
}


@dataclass
class RequestIdentity:
    """Tenant and user named by the request's credentials."""

    tenant_id: str
    user_id: str = ""
    api_key: bool = False
    extra: dict = field(default_factory=dict)


def api_path(request) -> str | None:
    """Path after ``/api/v1/`` without a trailing slash, or ``None``."""
    path = getattr(request, "path", "") or ""
    if not path.startswith(API_PREFIX):
        return None
    return path[len(API_PREFIX) :].strip("/")


def feature_for_path(path: str) -> str | None:
    """Feature key that gates ``path`` (after ``/api/v1/``), if any."""
    if FINDING_TRIAGE_PATH.match(path):
        return catalog.FEATURE_FINDING_TRIAGE
    for prefix, feature in FEATURE_PATH_PREFIXES:
        if path.startswith(prefix):
            return feature
    return None


def is_exempt(path: str) -> bool:
    return any(
        path == prefix.rstrip("/") or path.startswith(prefix)
        for prefix in EXEMPT_PREFIXES
    )


def allowed_while_inactive(path: str, method: str, user_id: str) -> bool:
    """Writes a read-only tenant may still make."""
    if path in READ_ONLY_ALLOWED_PATHS:
        return True
    if any(path.startswith(prefix) for prefix in READ_ONLY_ALLOWED_PREFIXES):
        return True
    # The user's own profile and password (``PATCH /users/<own id>``).
    if method in ("PATCH", "PUT") and user_id and path == f"users/{user_id}":
        return True
    return False


def error_response(code: str, title: str, detail: str, meta: dict | None = None):
    error = {"status": "403", "code": code, "title": title, "detail": detail}
    if meta:
        error["meta"] = meta
    return JsonResponse(
        {"errors": [error]}, status=403, content_type=JSONAPI_CONTENT_TYPE
    )


def _bearer_identity(token: str) -> RequestIdentity | None:
    from rest_framework_simplejwt.tokens import AccessToken

    try:
        validated = AccessToken(token)
    except Exception:
        # Invalid or expired: the view answers 401.
        return None
    tenant_id = validated.get("tenant_id")
    if not tenant_id:
        return None
    return RequestIdentity(
        tenant_id=str(tenant_id), user_id=str(validated.get("sub") or "")
    )


def _api_key_identity(raw_key: str) -> RequestIdentity | None:
    from api.db_router import MainRouter
    from api.models import TenantAPIKey, TenantAPIKeyManager
    from drf_simple_apikey.crypto import get_crypto

    try:
        _, key = raw_key.split(TenantAPIKeyManager.separator, 1)
        payload = get_crypto().decrypt(key)
        pk = payload.get("_pk") if isinstance(payload, dict) else None
    except Exception:
        return None
    if not pk:
        return None
    row = (
        TenantAPIKey.objects.using(MainRouter.admin_db)
        .filter(id=pk, revoked=False)
        .values_list("tenant_id", "entity_id")
        .first()
    )
    if row is None:
        return None
    return RequestIdentity(
        tenant_id=str(row[0]), user_id=str(row[1] or ""), api_key=True
    )


def request_identity(request) -> RequestIdentity | None:
    """Tenant claim of the bearer token or API key, without touching the body.

    Same claim the audit middleware and the views use (``tenant_id``).
    """
    header = (request.META.get("HTTP_AUTHORIZATION") or "").strip()
    if header.startswith("Bearer "):
        return _bearer_identity(header[len("Bearer ") :].strip())
    if header.startswith("Api-Key "):
        return _api_key_identity(header[len("Api-Key ") :].strip())
    return None


def decide(request, path: str, identity: RequestIdentity, entitlements):
    """The denial response for this request, or ``None`` to let it through."""
    from cloudsneeker_api.services import entitlements as service

    method = request.method
    mutating = method in MUTATING_METHODS

    if mutating and entitlements.read_only:
        if not allowed_while_inactive(path, method, identity.user_id):
            return error_response(
                CODE_SUBSCRIPTION_INACTIVE,
                "Subscription inactive",
                "This organization's subscription is "
                f"{entitlements.effective_status.replace('_', ' ')}. You can "
                "sign in and view data, but changes are disabled until the "
                "subscription is renewed.",
                {"status": entitlements.effective_status},
            )

    feature = feature_for_path(path)
    if identity.api_key and not entitlements.has_feature(catalog.FEATURE_API_ACCESS):
        feature = catalog.FEATURE_API_ACCESS
    if feature and not entitlements.has_feature(feature):
        label = FEATURE_LABELS.get(feature, feature)
        return error_response(
            CODE_FEATURE_NOT_IN_PLAN,
            "Feature not in plan",
            f"{label} is not included in the {entitlements.plan_name} plan.",
            {"feature": feature, "plan": entitlements.plan_code},
        )

    if method == "POST" and path in LIMITED_COLLECTIONS:
        limit_key, usage_key = LIMITED_COLLECTIONS[path]
        limit = entitlements.limit(limit_key)
        if limit is not None:
            used = service.usage_for_tenant(identity.tenant_id).get(usage_key) or 0
            if used >= limit:
                label = LIMIT_LABELS.get(limit_key, limit_key)
                return error_response(
                    CODE_PLAN_LIMIT_REACHED,
                    "Plan limit reached",
                    f"The {entitlements.plan_name} plan allows {limit} {label}; "
                    f"this organization already has {used}.",
                    {"limit": limit_key, "max": limit, "usage": used},
                )
    return None


class SubscriptionEnforcementMiddleware:
    """Refuse requests the tenant's subscription does not allow.

    Registered once in ``config/django/base.py`` (``cloudsneeker-hook``),
    last in ``MIDDLEWARE``.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            denial = self._check(request)
        except Exception:
            logger.exception("Subscription enforcement failed for %s", request.path)
            denial = None
        if denial is not None:
            return denial
        return self.get_response(request)

    @staticmethod
    def _check(request):
        path = api_path(request)
        if path is None or is_exempt(path):
            return None
        if request.method in ("OPTIONS", "HEAD"):
            return None
        identity = request_identity(request)
        if identity is None:
            return None

        from api.db_router import MainRouter
        from cloudsneeker_api.services import entitlements as service
        from django.db import transaction

        # A savepoint keeps a failed lookup (for example a database user
        # without access to the operator tables) from aborting a transaction
        # the request is already in.
        with transaction.atomic(using=MainRouter.admin_db):
            entitlements = service.for_tenant(identity.tenant_id)
            if entitlements.fallback:
                return None
            return decide(request, path, identity, entitlements)
