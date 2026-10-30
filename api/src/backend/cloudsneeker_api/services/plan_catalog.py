"""Plan catalogue constants and seeding (operator console, Phase 1).

Pure data plus seeding helpers that take model classes as arguments, so the
``0014_operator_console`` data migration (historical models) and the tests
(real models) run the same code. Nothing here imports Django models.
"""

from __future__ import annotations

import os
from typing import Any

# Feature keys a plan can include. The UI hides navigation for a missing key
# and the API refuses the matching paths with ``feature_not_in_plan``.
FEATURE_CLOUD_POSTURE = "cloud_posture"
FEATURE_ATTACK_PATHS = "attack_paths"
FEATURE_COMPLIANCE = "compliance"
FEATURE_APPLICATION_SECURITY = "application_security"
FEATURE_SAST = "sast"
FEATURE_GOVERNANCE = "governance"
FEATURE_REPORTS = "reports"
FEATURE_REPORT_SCHEDULES = "report_schedules"
FEATURE_SEEKER_AI = "seeker_ai"
FEATURE_FINDING_TRIAGE = "finding_triage"
FEATURE_AUDIT_LOG = "audit_log"
FEATURE_SSO = "sso"
FEATURE_API_ACCESS = "api_access"
FEATURE_INTEGRATIONS = "integrations"

FEATURE_KEYS: tuple[str, ...] = (
    FEATURE_CLOUD_POSTURE,
    FEATURE_ATTACK_PATHS,
    FEATURE_COMPLIANCE,
    FEATURE_APPLICATION_SECURITY,
    FEATURE_SAST,
    FEATURE_GOVERNANCE,
    FEATURE_REPORTS,
    FEATURE_REPORT_SCHEDULES,
    FEATURE_SEEKER_AI,
    FEATURE_FINDING_TRIAGE,
    FEATURE_AUDIT_LOG,
    FEATURE_SSO,
    FEATURE_API_ACCESS,
    FEATURE_INTEGRATIONS,
)

# Limit keys. ``None`` (or a missing key) means unlimited.
LIMIT_PROVIDERS = "providers"
LIMIT_USERS = "users"
LIMIT_APPLICATION_SECURITY_TARGETS = "application_security_targets"
LIMIT_SCANS_PER_MONTH = "scans_per_month"
LIMIT_REPORT_SCHEDULES = "report_schedules"
LIMIT_SEEKER_AI_REQUESTS_PER_MONTH = "seeker_ai_requests_per_month"

LIMIT_KEYS: tuple[str, ...] = (
    LIMIT_PROVIDERS,
    LIMIT_USERS,
    LIMIT_APPLICATION_SECURITY_TARGETS,
    LIMIT_SCANS_PER_MONTH,
    LIMIT_REPORT_SCHEDULES,
    LIMIT_SEEKER_AI_REQUESTS_PER_MONTH,
)

# Subscription statuses and billing sources.
STATUS_TRIAL = "trial"
STATUS_ACTIVE = "active"
STATUS_PAST_DUE = "past_due"
STATUS_SUSPENDED = "suspended"
STATUS_EXPIRED = "expired"
STATUS_CANCELLED = "cancelled"

STATUS_CHOICES = [
    (STATUS_TRIAL, "Trial"),
    (STATUS_ACTIVE, "Active"),
    (STATUS_PAST_DUE, "Past due"),
    (STATUS_SUSPENDED, "Suspended"),
    (STATUS_EXPIRED, "Expired"),
    (STATUS_CANCELLED, "Cancelled"),
]
# Statuses whose tenant is read-only (sign-in works, writes are refused).
INACTIVE_STATUSES = frozenset({STATUS_SUSPENDED, STATUS_EXPIRED, STATUS_CANCELLED})
# Statuses the expiry task moves to ``expired`` once their end date passes.
EXPIRABLE_STATUSES = frozenset({STATUS_TRIAL, STATUS_ACTIVE, STATUS_PAST_DUE})

BILLING_MANUAL = "manual"
BILLING_SOURCE_CHOICES = [
    (BILLING_MANUAL, "Manual"),
    ("aws_marketplace", "AWS Marketplace"),
    ("azure_marketplace", "Azure Marketplace"),
    ("self_hosted_licence", "Self-hosted licence"),
]

OPERATOR_ROLE_OWNER = "owner"
OPERATOR_ROLE_SUPPORT = "support"
OPERATOR_ROLE_BILLING = "billing"
OPERATOR_ROLE_READ_ONLY = "read_only"
OPERATOR_ROLE_CHOICES = [
    (OPERATOR_ROLE_OWNER, "Owner"),
    (OPERATOR_ROLE_SUPPORT, "Support"),
    (OPERATOR_ROLE_BILLING, "Billing"),
    (OPERATOR_ROLE_READ_ONLY, "Read only"),
]

LEGACY_PLAN_CODE = "legacy"
DEFAULT_PLAN_ENV = "CLOUDSNEEKER_DEFAULT_PLAN"


def _unlimited() -> dict[str, None]:
    return dict.fromkeys(LIMIT_KEYS)


# Proposed defaults (owner decision pending; editable in the console).
DEFAULT_PLANS: list[dict[str, Any]] = [
    {
        "code": LEGACY_PLAN_CODE,
        "name": "Legacy (unlimited)",
        "description": "Every feature and no limits. Tenants that existed "
        "before plans were introduced.",
        "features": list(FEATURE_KEYS),
        "limits": _unlimited(),
        "is_public": False,
        "sort_order": 0,
    },
    {
        "code": "starter",
        "name": "Starter",
        "description": "Cloud posture, compliance and on-demand reports for a "
        "small estate.",
        "features": [
            FEATURE_CLOUD_POSTURE,
            FEATURE_COMPLIANCE,
            FEATURE_REPORTS,
            FEATURE_FINDING_TRIAGE,
            FEATURE_INTEGRATIONS,
        ],
        "limits": {
            LIMIT_PROVIDERS: 3,
            LIMIT_USERS: 5,
            LIMIT_APPLICATION_SECURITY_TARGETS: 0,
            LIMIT_SCANS_PER_MONTH: 120,
            LIMIT_REPORT_SCHEDULES: 0,
            LIMIT_SEEKER_AI_REQUESTS_PER_MONTH: 0,
        },
        "is_public": True,
        "sort_order": 10,
    },
    {
        "code": "professional",
        "name": "Professional",
        "description": "Adds attack paths, application security, governance, "
        "scheduled reports, the assistant and the audit log.",
        "features": [
            FEATURE_CLOUD_POSTURE,
            FEATURE_ATTACK_PATHS,
            FEATURE_COMPLIANCE,
            FEATURE_APPLICATION_SECURITY,
            FEATURE_SAST,
            FEATURE_GOVERNANCE,
            FEATURE_REPORTS,
            FEATURE_REPORT_SCHEDULES,
            FEATURE_SEEKER_AI,
            FEATURE_FINDING_TRIAGE,
            FEATURE_AUDIT_LOG,
            FEATURE_API_ACCESS,
            FEATURE_INTEGRATIONS,
        ],
        "limits": {
            LIMIT_PROVIDERS: 15,
            LIMIT_USERS: 25,
            LIMIT_APPLICATION_SECURITY_TARGETS: 25,
            LIMIT_SCANS_PER_MONTH: 1000,
            LIMIT_REPORT_SCHEDULES: 10,
            LIMIT_SEEKER_AI_REQUESTS_PER_MONTH: 500,
        },
        "is_public": True,
        "sort_order": 20,
    },
    {
        "code": "enterprise",
        "name": "Enterprise",
        "description": "Every feature, single sign-on, no limits.",
        "features": list(FEATURE_KEYS),
        "limits": _unlimited(),
        "is_public": True,
        "sort_order": 30,
    },
    {
        "code": "managed",
        "name": "Managed",
        "description": "Every feature with no limits, operated on the "
        "customer's behalf.",
        "features": list(FEATURE_KEYS),
        "limits": _unlimited(),
        "is_public": True,
        "sort_order": 40,
    },
]

DEFAULT_PLANS_BY_CODE = {plan["code"]: plan for plan in DEFAULT_PLANS}


def default_plan_code() -> str:
    """``CLOUDSNEEKER_DEFAULT_PLAN`` (default ``legacy``) for new tenants."""
    value = (os.environ.get(DEFAULT_PLAN_ENV) or "").strip().lower()
    return value or LEGACY_PLAN_CODE


def clean_features(values: Any) -> list[str]:
    """Known feature keys from ``values``, de-duplicated, in catalogue order."""
    if not isinstance(values, (list, tuple, set, frozenset)):
        return []
    wanted = {str(value) for value in values}
    return [key for key in FEATURE_KEYS if key in wanted]


def clean_limits(values: Any) -> dict[str, int | None]:
    """Known limit keys from ``values``; non-negative integers or ``None``."""
    if not isinstance(values, dict):
        return {}
    cleaned: dict[str, int | None] = {}
    for key in LIMIT_KEYS:
        if key not in values:
            continue
        value = values[key]
        if value is None or value == "":
            cleaned[key] = None
            continue
        if isinstance(value, bool):
            raise ValueError(f"Limit '{key}' must be a number or null.")
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"Limit '{key}' must be a number or null.") from None
        if number < 0:
            raise ValueError(f"Limit '{key}' cannot be negative.")
        cleaned[key] = number
    return cleaned


def seed_plans(plan_model, using: str) -> int:
    """Create the default plans that do not exist yet; returns rows created.

    Existing plans are left as they are so operator edits survive a re-run.
    """
    created = 0
    for definition in DEFAULT_PLANS:
        _, was_created = plan_model.objects.using(using).get_or_create(
            code=definition["code"],
            defaults={key: value for key, value in definition.items() if key != "code"},
        )
        created += int(was_created)
    return created


def seed_subscriptions(
    tenant_model,
    subscription_model,
    plan_model,
    event_model,
    using: str,
    plan_code: str = LEGACY_PLAN_CODE,
    source: str = "migration",
) -> int:
    """Give every tenant without a subscription an active one on ``plan_code``.

    Returns the number of subscriptions created. Safe to run repeatedly.
    """
    plan = plan_model.objects.using(using).filter(code=plan_code).first()
    if plan is None:
        return 0
    existing = set(
        subscription_model.objects.using(using).values_list("tenant_id", flat=True)
    )
    created = 0
    for tenant in tenant_model.objects.using(using).all().iterator():
        if tenant.id in existing:
            continue
        subscription_model.objects.using(using).create(
            tenant_id=tenant.id,
            plan_id=plan.id,
            status=STATUS_ACTIVE,
            starts_at=tenant.inserted_at,
            billing_source=BILLING_MANUAL,
        )
        event_model.objects.using(using).create(
            tenant_id=tenant.id,
            action="created",
            source=source,
            changes={"plan": {"from": None, "to": plan.code}},
        )
        created += 1
    return created
