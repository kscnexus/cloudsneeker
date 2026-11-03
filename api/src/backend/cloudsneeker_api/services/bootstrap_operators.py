"""Grant the first operator owner from an environment variable.

``CLOUDSNEEKER_BOOTSTRAP_OPERATOR_EMAILS`` is a comma-separated list of
emails. While the platform has no active ``owner`` operator, a user whose
email is on the list becomes an ``owner`` operator when they sign up, or on
the next daily operator task if they already exist. Once any active owner
exists the variable does nothing, so registering a listed email later cannot
take over the console, and a revoked operator is never reactivated.

Sign-up does not verify email ownership, so the listed user should sign up
right after the variable is set. ``manage.py cloudsneeker_operator`` remains
the way to manage operators afterwards.
"""

from __future__ import annotations

import logging
import os

from cloudsneeker_api.services import plan_catalog as catalog

logger = logging.getLogger(__name__)

ENV_VAR = "CLOUDSNEEKER_BOOTSTRAP_OPERATOR_EMAILS"
ENV_ACTOR = "env"


def bootstrap_emails() -> set[str]:
    """Lower-cased emails from the env var; empty when unset."""
    raw = os.environ.get(ENV_VAR, "")
    return {email.strip().lower() for email in raw.split(",") if email.strip()}


def _db() -> str:
    from api.db_router import MainRouter

    return MainRouter.admin_db


def _has_active_owner() -> bool:
    from cloudsneeker_api.models import PlatformOperator

    return (
        PlatformOperator.objects.using(_db())
        .filter(role=catalog.OPERATOR_ROLE_OWNER, active=True)
        .exists()
    )


def grant_if_bootstrap(user) -> bool:
    """Make ``user`` an owner operator if the bootstrap rules allow it."""
    from cloudsneeker_api.models import OperatorAuditEvent, PlatformOperator

    if (user.email or "").lower() not in bootstrap_emails():
        return False
    if _has_active_owner():
        return False
    if PlatformOperator.objects.using(_db()).filter(user_id=user.id).exists():
        # Revoked or demoted on purpose; leave it to the CLI.
        return False
    operator = PlatformOperator.objects.using(_db()).create(
        user_id=user.id,
        role=catalog.OPERATOR_ROLE_OWNER,
        active=True,
        granted_by=ENV_ACTOR,
    )
    OperatorAuditEvent.objects.using(_db()).create(
        actor_email=ENV_ACTOR,
        action="operator.grant",
        target_type="platform_operator",
        target_id=str(operator.id),
        changed_fields=["role", "active"],
        metadata={"email": user.email, "role": operator.role},
    )
    logger.info("Granted bootstrap operator owner to %s", user.email)
    return True


def reconcile() -> int:
    """Grant existing users on the list; returns how many were granted."""
    from api.models import User

    emails = bootstrap_emails()
    if not emails or _has_active_owner():
        return 0
    for email in sorted(emails):
        user = User.objects.using(_db()).filter(email__iexact=email).first()
        if user is not None and grant_if_bootstrap(user):
            return 1  # One owner ends the bootstrap.
    return 0
