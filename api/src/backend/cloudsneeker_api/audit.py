"""User-action audit log (EB-007).

One middleware records every mutating ``/api/v1/`` request (POST, PUT, PATCH,
DELETE) after the view has answered, and the token endpoints record sign-in
success and failure. Views stay untouched: the action name comes from the
resolved route (router basename + view action, or the URL name), so new
upstream routes are still audited under a derived name.

Rules:

* Auditing never breaks a request. Every failure is logged and swallowed.
* Rows are written in an RLS transaction for the tenant of the request.
* ``metadata`` carries field *names* and non-secret context only. Request
  values (passwords, secrets, tokens, keys) are never stored.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

API_PREFIX = "/api/v1/"
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
USER_AGENT_MAX = 512
LABEL_MAX = 255
PATH_MAX = 512
MAX_FIELD_NAMES = 50
# Bodies above this size, or that are not JSON, are not parsed for field names.
MAX_AUDITED_BODY_BYTES = 1024 * 1024
MAX_FAILED_SIGN_IN_TENANTS = 10

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"

# Sign-in endpoints (upstream ``api.v1.urls`` names) and their method label.
SIGN_IN_URL_NAMES = {
    "token-obtain": "password",
    "token-saml": "saml",
    "token-google": "google",
    "token-github": "github",
}
SWITCH_TENANT_URL_NAME = "token-switch"

# Reads worth auditing (exports of sensitive data): URL name -> action.
AUDITED_READ_URL_NAMES = {
    "audit-events-export": ("audit_log.export", "audit_log"),
}
AUDITED_READ_PATHS = ("/api/v1/audit-events/export",)

# POSTs that only read or preview; they change nothing worth auditing.
SKIPPED_URL_NAMES = frozenset(
    {
        "token-refresh",
        "attack-paths-scans-queries-run",
        "attack-paths-scans-queries-custom",
        "alert-rules-preview",
        "alert-recipient-confirm",
        "alert-recipient-unsubscribe",
        "integrations-slack-oauth-authorize-url",
        "slack-oauth-authorize-url",
        "schema",
    }
)

# Router basename or URL-name stem -> audit namespace.
RESOURCE_NAMESPACES = {
    "user": "user",
    "tenant": "tenant",
    "provider": "provider",
    "providergroup": "provider_group",
    "providersecret": "provider_secret",
    "scan": "scan",
    "task": "task",
    "role": "role",
    "integration": "integration",
    "integration-jira": "integration",
    "processor": "processor",
    "saml-config": "saml_config",
    "lighthouseconfiguration": "lighthouse_config",
    "lighthouse-configurations": "lighthouse_config",
    "lighthouse-providers": "lighthouse_config",
    "api-key": "api_key",
    "mute-rule": "mute_rule",
    "tenant-membership": "membership",
    "user-membership": "membership",
    "invitation": "invitation",
    "invitation-accept": "invitation",
    "schedule": "scan_schedule",
    "finding": "finding",
    # Cloudsneeker routes.
    "scan-configurations": "scan_profile",
    "alert-rules": "alert_rule",
    "alert-recipients": "alert_recipient",
    "ingestions": "ingestion",
    "email-delivery-config": "email_config",
    "slack-app-config": "slack_app_config",
    "custodian-policies": "custodian_policy",
    "custodian-runs": "custodian_run",
    "trivy-targets": "trivy_target",
    "trivy-runs": "trivy_run",
    "report-runs": "report",
    "report-schedules": "report_schedule",
    "report-share-links": "report.share_link",
    "finding-triages": "finding_triage",
}

# URL names of non-router views -> (namespace, verb by HTTP method or None).
URL_NAME_ACTIONS = {
    "user-roles-relationship": "user.roles",
    "role-provider-groups-relationship": "role.provider_groups",
    "provider_group-providers-relationship": "provider_group.providers",
    "slack-oauth-exchange": "integration.slack_connect",
}

RELATIONSHIP_VERBS = {
    "POST": "add",
    "PATCH": "update",
    "PUT": "update",
    "DELETE": "remove",
}
VIEW_ACTION_VERBS = {
    "create": "create",
    "update": "update",
    "partial_update": "update",
    "destroy": "delete",
}
METHOD_VERBS = {
    "POST": "create",
    "PUT": "update",
    "PATCH": "update",
    "DELETE": "delete",
}

# (namespace, verb) -> final action, where the generic name reads badly.
ACTION_OVERRIDES = {
    ("scan", "create"): "scan.launch",
    ("report", "create"): "report.generate",
    ("report", "shares"): "report.share_link.create",
    ("report.share_link", "revoke"): "report.share_link.revoke",
    ("invitation", "accept"): "invitation.accept",
    ("email_config", "create"): "email_config.update",
    ("task", "delete"): "task.revoke",
    ("integration", "connection"): "integration.connection_test",
    ("provider", "connection"): "provider.connection_test",
    ("integration", "dispatches"): "integration.jira_dispatch",
}

# Target type recorded for each namespace (defaults to the namespace).
TARGET_TYPES = {
    "report": "report_run",
    "report.share_link": "report_share_link",
    "user.roles": "user",
    "role.provider_groups": "role",
    "provider_group.providers": "provider_group",
    "integration.slack_connect": "integration",
}

# Response attributes tried, in order, for a human label of the target.
LABEL_ATTRIBUTES = ("name", "alias", "email", "uid", "title", "prefix", "report_type")

# Field names that are never written to metadata, even as names.
SENSITIVE_FIELD_HINTS = ("password", "secret", "token", "key", "credential")


@dataclass
class AuditRecord:
    """Everything needed to write one audit row."""

    tenant_id: str
    action: str
    outcome: str = OUTCOME_SUCCESS
    actor_id: str | None = None
    actor_email: str = ""
    target_type: str = ""
    target_id: str = ""
    target_label: str = ""
    status_code: int | None = None
    ip_address: str | None = None
    user_agent: str = ""
    request_id: str = ""
    method: str = ""
    path: str = ""
    metadata: dict = field(default_factory=dict)


# --- Writing ------------------------------------------------------------------


def write_event(record: AuditRecord):
    """Insert one audit row in an RLS transaction; never raises.

    Returns:
        The created ``AuditEvent``, or ``None`` when writing failed.
    """
    try:
        from api.db_router import MainRouter
        from api.db_utils import rls_transaction
        from cloudsneeker_api.models import AuditEvent

        with rls_transaction(record.tenant_id, using=MainRouter.default_db):
            return AuditEvent.objects.using(MainRouter.default_db).create(
                tenant_id=record.tenant_id,
                action=record.action[:100],
                outcome=record.outcome,
                actor_id=record.actor_id or None,
                actor_email=(record.actor_email or "")[:254],
                target_type=(record.target_type or "")[:64],
                target_id=str(record.target_id or "")[:255],
                target_label=str(record.target_label or "")[:LABEL_MAX],
                status_code=record.status_code,
                ip_address=record.ip_address,
                user_agent=(record.user_agent or "")[:USER_AGENT_MAX],
                request_id=(record.request_id or "")[:64],
                method=record.method[:10],
                path=record.path[:PATH_MAX],
                metadata=record.metadata or {},
            )
    except Exception:
        logger.exception(
            "Audit event not recorded tenant=%s action=%s",
            record.tenant_id,
            record.action,
        )
        return None


def record_event(tenant_id: str, action: str, request=None, **fields: Any):
    """Record an event from code that is not a request (or adds detail).

    Args:
        tenant_id: Tenant the event belongs to.
        action: Namespaced action, e.g. ``"report.share_link.create"``.
        request: Optional Django or DRF request for actor, IP, and agent.
        **fields: Any other ``AuditRecord`` field.
    """
    record = AuditRecord(tenant_id=str(tenant_id), action=action, **fields)
    if request is not None:
        _fill_request_context(record, getattr(request, "_request", request))
        user = getattr(request, "user", None)
        if user is not None and getattr(user, "is_authenticated", False):
            record.actor_id = record.actor_id or str(user.id)
            record.actor_email = record.actor_email or getattr(user, "email", "")
    return write_event(record)


# --- Request helpers ------------------------------------------------------------


def client_ip(request) -> str | None:
    """First valid address of ``X-Forwarded-For`` (ALB), else ``REMOTE_ADDR``."""
    meta = getattr(request, "META", {}) or {}
    candidates = []
    forwarded = meta.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        candidates.extend(part.strip() for part in forwarded.split(","))
    candidates.append(meta.get("REMOTE_ADDR", ""))
    for candidate in candidates:
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def request_id() -> str:
    try:
        from django_guid import get_guid

        return get_guid() or ""
    except Exception:
        return ""


def _fill_request_context(record: AuditRecord, request) -> None:
    meta = getattr(request, "META", {}) or {}
    record.ip_address = record.ip_address or client_ip(request)
    record.user_agent = (
        record.user_agent or meta.get("HTTP_USER_AGENT", "")[:USER_AGENT_MAX]
    )
    record.request_id = record.request_id or request_id()
    record.method = record.method or getattr(request, "method", "") or ""
    record.path = record.path or (getattr(request, "path", "") or "")[:PATH_MAX]


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in SENSITIVE_FIELD_HINTS)


def field_names(body: Any) -> dict:
    """Names of the attributes and relationships a JSON body sets.

    Only keys are returned. Keys that look like secrets are reported as
    ``secret_fields_changed`` instead of by name.
    """
    if not isinstance(body, dict):
        return {}
    data = body.get("data", body)
    if isinstance(data, list):
        data = data[0] if data and isinstance(data[0], dict) else {}
    if not isinstance(data, dict):
        return {}
    attributes = data.get("attributes", data if "type" not in data else {})
    relationships = data.get("relationships", {})
    result: dict = {}
    names: list[str] = []
    secret_changed = False
    if isinstance(attributes, dict):
        for key in attributes:
            if not isinstance(key, str) or key in ("id", "type"):
                continue
            if _is_sensitive_name(key):
                secret_changed = True
                continue
            names.append(key)
    if names:
        result["fields"] = sorted(names)[:MAX_FIELD_NAMES]
    if isinstance(relationships, dict) and relationships:
        result["relationships"] = sorted(
            key for key in relationships if isinstance(key, str)
        )[:MAX_FIELD_NAMES]
    if secret_changed:
        result["secret_fields_changed"] = True
    return result


def read_json_body(request) -> Any:
    """Parse a small JSON request body before the view consumes the stream.

    Reading ``request.body`` caches it, so DRF parses the same bytes after.
    Uploads and large bodies are left alone.
    """
    content_type = (request.META.get("CONTENT_TYPE") or "").lower()
    if "json" not in content_type:
        return None
    try:
        length = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        return None
    if length <= 0 or length > MAX_AUDITED_BODY_BYTES:
        return None
    try:
        return json.loads(request.body or b"null")
    except Exception:
        return None


# --- Route -> action ------------------------------------------------------------


@dataclass
class RouteAction:
    action: str
    target_type: str
    namespace: str
    verb: str


def _basename_and_view_action(resolver_match, method: str) -> tuple[str, str | None]:
    func = getattr(resolver_match, "func", None)
    initkwargs = getattr(func, "initkwargs", None) or {}
    actions = getattr(func, "actions", None) or {}
    url_name = getattr(resolver_match, "url_name", "") or ""
    view_action = actions.get(method.lower())
    basename = initkwargs.get("basename")
    if not basename:
        basename = url_name
        for suffix in ("-list", "-detail"):
            if basename.endswith(suffix):
                basename = basename[: -len(suffix)]
                break
    return basename, view_action


def resolve_action(resolver_match, method: str) -> RouteAction | None:
    """Map a resolved mutating route to an audit action, or ``None`` to skip."""
    if resolver_match is None:
        return None
    url_name = getattr(resolver_match, "url_name", "") or ""
    if url_name in SKIPPED_URL_NAMES:
        return None

    if url_name in URL_NAME_ACTIONS:
        namespace = URL_NAME_ACTIONS[url_name]
        verb = RELATIONSHIP_VERBS.get(method, "update")
        if namespace == "integration.slack_connect":
            return RouteAction(namespace, "integration", namespace, verb)
    else:
        basename, view_action = _basename_and_view_action(resolver_match, method)
        if not basename:
            return None
        namespace = RESOURCE_NAMESPACES.get(basename, basename.replace("-", "_"))
        if view_action:
            verb = VIEW_ACTION_VERBS.get(view_action, view_action)
        else:
            verb = METHOD_VERBS.get(method, method.lower())

    action = ACTION_OVERRIDES.get((namespace, verb), f"{namespace}.{verb}")
    target_type = TARGET_TYPES.get(namespace, namespace)
    return RouteAction(action, target_type, namespace, verb)


def _document(data: Any) -> dict:
    """The resource object of a response, whether wrapped in ``data`` or not."""
    if not isinstance(data, dict):
        return {}
    inner = data.get("data")
    if isinstance(inner, dict):
        return inner
    return data


def target_from_response(resolver_match, response) -> tuple[str, str]:
    """``(id, label)`` from the URL kwargs and the response body."""
    kwargs = getattr(resolver_match, "kwargs", {}) or {}
    target_id = str(kwargs.get("pk") or "")
    document = _document(getattr(response, "data", None))
    if not target_id and document.get("id"):
        target_id = str(document.get("id"))
    if not target_id:
        for key, value in kwargs.items():
            if key.endswith("_pk") and value:
                target_id = str(value)
                break
    attributes = document.get("attributes")
    if not isinstance(attributes, dict):
        attributes = document
    label = ""
    for name in LABEL_ATTRIBUTES:
        value = attributes.get(name) if isinstance(attributes, dict) else None
        if isinstance(value, str) and value:
            label = value
            break
    return target_id, label[:LABEL_MAX]


# --- Sign-in --------------------------------------------------------------------


def _find_access_token(data: Any) -> str | None:
    if isinstance(data, dict):
        token = data.get("access")
        if isinstance(token, str) and token:
            return token
        for value in data.values():
            found = _find_access_token(value)
            if found:
                return found
    return None


def token_claims(response) -> dict:
    """Claims of the access token a token endpoint just issued, or ``{}``."""
    token = _find_access_token(getattr(response, "data", None))
    if not token:
        return {}
    try:
        import jwt

        # Issued by this process a moment ago; only the claims are needed.
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return {}


def _body_attribute(body: Any, name: str) -> str:
    document = _document(body)
    attributes = document.get("attributes", document) if document else {}
    value = attributes.get(name) if isinstance(attributes, dict) else None
    return value if isinstance(value, str) else ""


def _user_email(user_id: str) -> str:
    try:
        from api.db_router import MainRouter
        from api.models import User

        return (
            User.objects.using(MainRouter.admin_db)
            .filter(id=user_id)
            .values_list("email", flat=True)
            .first()
            or ""
        )
    except Exception:
        return ""


def failed_sign_in_tenants(email: str, tenant_id: str = "") -> list[tuple[str, str]]:
    """``(user_id, tenant_id)`` pairs to record a failed sign-in against.

    Only known users have a tenant. When the request named a tenant the user
    belongs to, only that tenant is used; otherwise every membership (capped).
    """
    if not email:
        return []
    try:
        from api.db_router import MainRouter
        from api.models import Membership, User

        user = (
            User.objects.using(MainRouter.admin_db)
            .filter(email__iexact=email)
            .values_list("id", flat=True)
            .first()
        )
        if user is None:
            return []
        tenants = list(
            Membership.objects.using(MainRouter.admin_db)
            .filter(user_id=user)
            .order_by("date_joined")
            .values_list("tenant_id", flat=True)[:MAX_FAILED_SIGN_IN_TENANTS]
        )
        tenant_ids = [str(value) for value in tenants]
        if tenant_id and tenant_id in tenant_ids:
            tenant_ids = [tenant_id]
        return [(str(user), value) for value in tenant_ids]
    except Exception:
        logger.exception("Audit could not resolve tenants for a failed sign-in")
        return []


# --- Middleware -----------------------------------------------------------------


class AuditLogMiddleware:
    """Record mutating API requests and sign-ins as ``AuditEvent`` rows.

    Registered once in ``config/django/base.py`` (``cloudsneeker-hook``).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not self._applies(request):
            return self.get_response(request)

        body = None
        try:
            body = read_json_body(request)
        except Exception:
            body = None

        response = self.get_response(request)

        try:
            self._record(request, response, body)
        except Exception:
            logger.exception("Audit middleware failed for %s", request.path)
        return response

    @staticmethod
    def _applies(request) -> bool:
        path = request.path or ""
        if not path.startswith(API_PREFIX):
            return False
        if request.method in MUTATING_METHODS:
            return True
        return request.method == "GET" and path.rstrip("/") in AUDITED_READ_PATHS

    def _record(self, request, response, body) -> None:
        match = getattr(request, "resolver_match", None)
        url_name = getattr(match, "url_name", "") or ""
        status_code = getattr(response, "status_code", 0) or 0
        outcome = OUTCOME_SUCCESS if status_code < 400 else OUTCOME_FAILURE

        if url_name in SIGN_IN_URL_NAMES:
            self._record_sign_in(request, response, body, url_name, outcome)
            return
        if url_name == SWITCH_TENANT_URL_NAME:
            self._record_switch(request, response, outcome)
            return

        auth = getattr(request, "auth", None)
        tenant_id = auth.get("tenant_id") if hasattr(auth, "get") else None
        if not tenant_id:
            # Unauthenticated (sign-up, public endpoints) or no tenant claim.
            return

        if request.method == "GET":
            if url_name not in AUDITED_READ_URL_NAMES:
                return
            action, target_type = AUDITED_READ_URL_NAMES[url_name]
            route = RouteAction(action, target_type, target_type, "export")
        else:
            route = resolve_action(match, request.method)
        if route is None:
            return

        target_id, target_label = target_from_response(match, response)
        if (
            route.action == "tenant.delete"
            and outcome == OUTCOME_SUCCESS
            and target_id == str(tenant_id)
        ):
            # The tenant and its audit log are being removed; nothing to keep.
            return
        metadata = field_names(body)
        api_key_prefix = auth.get("api_key_prefix") if hasattr(auth, "get") else None
        if api_key_prefix:
            metadata["api_key_prefix"] = str(api_key_prefix)
        view_action = _basename_and_view_action(match, request.method)[1]
        if view_action and view_action not in VIEW_ACTION_VERBS:
            metadata["view_action"] = view_action

        user = getattr(request, "user", None)
        record = AuditRecord(
            tenant_id=str(tenant_id),
            action=route.action,
            outcome=outcome,
            actor_id=str(user.id)
            if getattr(user, "is_authenticated", False)
            else (str(auth.get("sub")) if auth.get("sub") else None),
            actor_email=getattr(user, "email", "") or "",
            target_type=route.target_type,
            target_id=target_id,
            target_label=target_label,
            status_code=status_code,
            metadata=metadata,
        )
        _fill_request_context(record, request)
        write_event(record)

    def _record_sign_in(self, request, response, body, url_name, outcome) -> None:
        method = SIGN_IN_URL_NAMES[url_name]
        status_code = getattr(response, "status_code", 0) or 0
        if outcome == OUTCOME_SUCCESS:
            claims = token_claims(response)
            tenant_id = claims.get("tenant_id")
            user_id = claims.get("sub") or claims.get("user_id")
            if not tenant_id:
                return
            record = AuditRecord(
                tenant_id=str(tenant_id),
                action="auth.sign_in",
                actor_id=str(user_id) if user_id else None,
                actor_email=_body_attribute(body, "email")
                or (_user_email(str(user_id)) if user_id else ""),
                target_type="user",
                target_id=str(user_id or ""),
                status_code=status_code,
                metadata={"method": method},
            )
            _fill_request_context(record, request)
            write_event(record)
            return

        email = _body_attribute(body, "email")
        requested_tenant = _body_attribute(body, "tenant_id")
        reason = "throttled" if status_code == 429 else "rejected"
        for user_id, tenant_id in failed_sign_in_tenants(email, requested_tenant):
            record = AuditRecord(
                tenant_id=tenant_id,
                action="auth.sign_in_failed",
                outcome=OUTCOME_FAILURE,
                actor_id=user_id,
                actor_email=email,
                target_type="user",
                target_id=user_id,
                status_code=status_code,
                metadata={"method": method, "reason": reason},
            )
            _fill_request_context(record, request)
            write_event(record)

    def _record_switch(self, request, response, outcome) -> None:
        auth = getattr(request, "auth", None)
        claims = token_claims(response) if outcome == OUTCOME_SUCCESS else {}
        tenant_id = claims.get("tenant_id") or (
            auth.get("tenant_id") if hasattr(auth, "get") else None
        )
        if not tenant_id:
            return
        user = getattr(request, "user", None)
        authenticated = getattr(user, "is_authenticated", False)
        record = AuditRecord(
            tenant_id=str(tenant_id),
            action="auth.switch_tenant",
            outcome=outcome,
            actor_id=str(user.id) if authenticated else claims.get("sub"),
            actor_email=getattr(user, "email", "") if authenticated else "",
            target_type="tenant",
            target_id=str(tenant_id),
            status_code=getattr(response, "status_code", None),
        )
        _fill_request_context(record, request)
        write_event(record)


# --- Retention ------------------------------------------------------------------

DEFAULT_RETENTION_DAYS = 365


def retention_days() -> int:
    """``AUDIT_LOG_RETENTION_DAYS`` (default 365; values below 1 use the default)."""
    import os

    try:
        days = int(os.environ.get("AUDIT_LOG_RETENTION_DAYS", DEFAULT_RETENTION_DAYS))
    except ValueError:
        return DEFAULT_RETENTION_DAYS
    return days if days >= 1 else DEFAULT_RETENTION_DAYS


def purge_tenant_events(tenant_id: str, older_than_days: int) -> int:
    """Delete one tenant's events older than the window; returns rows removed."""
    from datetime import timedelta

    from api.db_router import MainRouter
    from api.db_utils import rls_transaction
    from cloudsneeker_api.models import AuditEvent
    from django.utils import timezone

    cutoff = timezone.now() - timedelta(days=older_than_days)
    with rls_transaction(str(tenant_id), using=MainRouter.default_db):
        deleted, _ = (
            AuditEvent.objects.using(MainRouter.default_db)
            .filter(tenant_id=tenant_id, inserted_at__lt=cutoff)
            .delete()
        )
    return deleted


def purge_all_tenants(tenant_ids: Iterable[str], older_than_days: int) -> int:
    total = 0
    for tenant_id in tenant_ids:
        try:
            total += purge_tenant_events(str(tenant_id), older_than_days)
        except Exception:
            logger.exception("Audit retention failed for tenant=%s", tenant_id)
    return total
