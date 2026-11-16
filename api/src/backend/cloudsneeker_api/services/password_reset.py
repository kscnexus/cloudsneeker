"""Operator password reset: a one-time temporary password for a user account.

Used by ``POST /operator/tenants/{tenant_id}/users/{user_id}/password-reset``
(``views_operator``). The reset:

* generates a random temporary password that passes Django's
  ``AUTH_PASSWORD_VALIDATORS`` and stores only its hash (``set_password``);
* blacklists every outstanding refresh token of the user, so no session can
  get a new access token. Access tokens already issued stay valid until they
  expire (``DJANGO_ACCESS_TOKEN_LIFETIME``, 30 minutes by default);
* clears the per-account sign-in lockout (``login_guard``), so the user can
  sign in with the temporary password at once.

The temporary password is returned to the caller once. It is never logged
or stored in clear text.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass

logger = logging.getLogger(__name__)

TEMPORARY_PASSWORD_LENGTH = 20
# Characters that are easy to tell apart when read aloud or copied by hand.
_LOWER = "abcdefghijkmnpqrstuvwxyz"
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_DIGITS = "23456789"
_SPECIAL = "!@#$%^&*-_=+?"
_ALPHABET = _LOWER + _UPPER + _DIGITS + _SPECIAL
_MAX_ATTEMPTS = 20


class PasswordResetError(Exception):
    """The account cannot be reset by an operator."""


@dataclass(frozen=True)
class PasswordResetResult:
    user: object
    temporary_password: str
    revoked_sessions: int
    lockout_cleared: bool


def _admin_db() -> str:
    from api.db_router import MainRouter

    return MainRouter.admin_db


def generate_temporary_password(user=None) -> str:
    """A random password with every character class the validators require."""
    from django.contrib.auth.password_validation import validate_password
    from django.core.exceptions import ValidationError

    for _ in range(_MAX_ATTEMPTS):
        required = [
            secrets.choice(_LOWER),
            secrets.choice(_UPPER),
            secrets.choice(_DIGITS),
            secrets.choice(_SPECIAL),
        ]
        rest = [
            secrets.choice(_ALPHABET)
            for _ in range(TEMPORARY_PASSWORD_LENGTH - len(required))
        ]
        characters = required + rest
        secrets.SystemRandom().shuffle(characters)
        candidate = "".join(characters)
        try:
            validate_password(candidate, user)
        except ValidationError:
            continue
        return candidate
    raise PasswordResetError("Could not generate a temporary password.")


def revoke_refresh_tokens(user) -> int:
    """Blacklist every outstanding refresh token of ``user``; the count."""
    from rest_framework_simplejwt.token_blacklist.models import (
        BlacklistedToken,
        OutstandingToken,
    )

    alias = _admin_db()
    outstanding = OutstandingToken.objects.using(alias).filter(user_id=user.id)
    already = set(
        BlacklistedToken.objects.using(alias)
        .filter(token__user_id=user.id)
        .values_list("token_id", flat=True)
    )
    revoked = 0
    for token in outstanding:
        if token.id in already:
            continue
        BlacklistedToken.objects.using(alias).get_or_create(token=token)
        revoked += 1
    return revoked


def clear_lockout(email: str) -> bool:
    """Clear the sign-in lockout of ``email``; False when the cache is down."""
    from cloudsneeker_api import login_guard

    try:
        login_guard.clear_failures(email)
    except Exception:
        logger.warning("Sign-in lockout not cleared after a password reset")
        return False
    return True


def tenant_member(tenant_id, user_id):
    """The user with a membership in ``tenant_id``, or ``None``."""
    from api.models import Membership

    membership = (
        Membership.objects.using(_admin_db())
        .select_related("user")
        .filter(tenant_id=tenant_id, user_id=user_id)
        .first()
    )
    return membership.user if membership else None


def is_platform_operator(user) -> bool:
    from cloudsneeker_api.models import PlatformOperator

    return (
        PlatformOperator.objects.using(_admin_db())
        .filter(user_id=user.id, active=True)
        .exists()
    )


def reset_password(user, *, actor) -> PasswordResetResult:
    """Give ``user`` a temporary password and end their sessions.

    Refuses the operator's own account and the accounts of active platform
    operators: an operator must not take over another operator's role.
    """
    from django.db import transaction

    if str(user.id) == str(getattr(actor, "id", "")):
        raise PasswordResetError("You cannot reset your own password here.")
    if is_platform_operator(user):
        raise PasswordResetError(
            "This account belongs to a platform operator and cannot be reset here."
        )
    temporary_password = generate_temporary_password(user)
    alias = _admin_db()
    with transaction.atomic(using=alias):
        user.set_password(temporary_password)
        user.save(using=alias, update_fields=["password"])
        revoked = revoke_refresh_tokens(user)
    cleared = clear_lockout(user.email)
    return PasswordResetResult(
        user=user,
        temporary_password=temporary_password,
        revoked_sessions=revoked,
        lockout_cleared=cleared,
    )
