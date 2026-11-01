"""Multi-factor authentication for password users (EB-008).

Users who sign in with a password can add an authenticator app (TOTP).
Once confirmed, ``POST /tokens`` needs a code from it (or a recovery code).
A tenant administrator can require MFA: password users of that tenant who
have not enrolled can then only reach the MFA setup endpoints.

SAML and social sign-in users are never asked: their identity provider owns
the second factor. Rows live outside row-level security and are read and
written through the admin connection.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from cloudsneeker_api.services import totp
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

RECOVERY_CODE_COUNT = 10
# 10 base32 characters, shown as two groups of five: about 50 bits each.
RECOVERY_CODE_LENGTH = 10
_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
ENROLMENT_CACHE_SECONDS = 60
_ENROLMENT_CACHE_KEY = "cloudsneeker:mfa:enrolment:{user_id}:{tenant_id}"


CODE_INVALID = "mfa_invalid"


class MfaError(Exception):
    """A request the MFA state does not allow; ``code`` is the API error code."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _db() -> str:
    from api.db_router import MainRouter

    return MainRouter.admin_db


def _user_mfa_model():
    from cloudsneeker_api.models import UserMfa

    return UserMfa


def _policy_model():
    from cloudsneeker_api.models import TenantMfaPolicy

    return TenantMfaPolicy


# --- Recovery codes -----------------------------------------------------------


def _hash_recovery_code(code: str) -> str:
    key = settings.SECRET_KEY.encode()
    return hmac.new(key, code.encode(), hashlib.sha256).hexdigest()


def _normalize_recovery_code(code: str | None) -> str:
    return totp.normalize_code(code).upper()


def new_recovery_codes() -> list[str]:
    """Fresh recovery codes, formatted ``XXXXX-XXXXX``."""
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = "".join(
            secrets.choice(_RECOVERY_ALPHABET) for _ in range(RECOVERY_CODE_LENGTH)
        )
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def _store_recovery_codes(mfa, codes: list[str]) -> None:
    mfa.recovery_code_hashes = [
        _hash_recovery_code(_normalize_recovery_code(code)) for code in codes
    ]


# --- Who is asked -------------------------------------------------------------


def is_password_user(user) -> bool:
    """``False`` for users who sign in through SAML or a social provider."""
    if not user.has_usable_password():
        return False
    try:
        from allauth.socialaccount.models import SocialAccount
    except Exception:
        return True
    return not SocialAccount.objects.using(_db()).filter(user_id=user.pk).exists()


def get_user_mfa(user_id):
    return _user_mfa_model().objects.using(_db()).filter(user_id=user_id).first()


def is_enabled(user_id) -> bool:
    mfa = get_user_mfa(user_id)
    return bool(mfa and mfa.enabled)


def tenant_requires_mfa(tenant_id) -> bool:
    if not tenant_id:
        return False
    return (
        _policy_model()
        .objects.using(_db())
        .filter(tenant_id=tenant_id, require_mfa=True)
        .exists()
    )


def enrolment_required(user_id, tenant_id) -> bool:
    """The tenant requires MFA and this password user has not enrolled."""
    if not user_id or not tenant_id:
        return False
    key = _ENROLMENT_CACHE_KEY.format(user_id=user_id, tenant_id=tenant_id)
    cached = cache.get(key)
    if cached is not None:
        return cached
    required = False
    if tenant_requires_mfa(tenant_id) and not is_enabled(user_id):
        from api.models import User

        user = User.objects.using(_db()).filter(pk=user_id).first()
        required = bool(user and is_password_user(user))
    cache.set(key, required, ENROLMENT_CACHE_SECONDS)
    return required


def _forget_enrolment(user_id=None, tenant_id=None) -> None:
    """Drop cached answers after enrolment or policy changes."""
    from api.models import Membership

    memberships = Membership.objects.using(_db())
    if user_id:
        memberships = memberships.filter(user_id=user_id)
    if tenant_id:
        memberships = memberships.filter(tenant_id=tenant_id)
    cache.delete_many(
        [
            _ENROLMENT_CACHE_KEY.format(user_id=user, tenant_id=tenant)
            for user, tenant in memberships.values_list("user_id", "tenant_id")
        ]
    )


# --- Status -------------------------------------------------------------------


def status(user, tenant_id) -> dict:
    mfa = get_user_mfa(user.pk)
    password_user = is_password_user(user)
    requires = tenant_requires_mfa(tenant_id)
    enabled = bool(mfa and mfa.enabled)
    return {
        "enabled": enabled,
        "pending": bool(mfa and not mfa.enabled),
        "applies": password_user,
        "tenant_requires_mfa": requires,
        "enrolment_required": requires and password_user and not enabled,
        "recovery_codes_remaining": len(mfa.recovery_code_hashes) if enabled else 0,
        "confirmed_at": mfa.confirmed_at.isoformat() if enabled else None,
    }


# --- Enrolment ----------------------------------------------------------------


def begin_enrolment(user) -> dict:
    """Start (or restart) enrolment with a new secret; not active until confirmed."""
    from cloudsneeker_api.brand import brand

    if not is_password_user(user):
        raise MfaError(
            "mfa_not_applicable",
            "Your organization's identity provider handles sign-in for this "
            "account, so MFA is managed there.",
        )
    mfa = get_user_mfa(user.pk)
    if mfa and mfa.enabled:
        raise MfaError("mfa_already_enabled", "MFA is already on for this account.")
    if mfa is None:
        mfa = _user_mfa_model()(user_id=user.pk)
    secret = totp.generate_secret()
    mfa.secret = secret
    mfa.last_used_step = None
    mfa.recovery_code_hashes = []
    mfa.save(using=_db())
    return {
        "secret": secret,
        "otpauth_uri": totp.provisioning_uri(secret, user.email, brand.name),
    }


def confirm_enrolment(user, code: str) -> list[str]:
    """Turn MFA on with a first code; returns the recovery codes (shown once)."""
    mfa = get_user_mfa(user.pk)
    if mfa is None or mfa.enabled:
        raise MfaError(
            "mfa_not_pending", "Start setting up an authenticator app first."
        )
    step = totp.matching_step(mfa.secret, code)
    if step is None:
        raise MfaError(
            CODE_INVALID,
            "That code did not match. Check the time on your phone and try the "
            "newest code.",
        )
    codes = new_recovery_codes()
    _store_recovery_codes(mfa, codes)
    mfa.last_used_step = step
    mfa.confirmed_at = timezone.now()
    mfa.save(using=_db())
    _forget_enrolment(user_id=user.pk)
    return codes


# --- Second factor ------------------------------------------------------------


def verify_second_factor(user_id, code: str | None) -> bool:
    """Accept a fresh TOTP code or an unused recovery code (then spend it)."""
    if not code:
        return False
    from django.db import transaction

    with transaction.atomic(using=_db()):
        mfa = (
            _user_mfa_model()
            .objects.using(_db())
            .select_for_update()
            .filter(user_id=user_id, confirmed_at__isnull=False)
            .first()
        )
        if mfa is None:
            return False
        step = totp.matching_step(mfa.secret, code, after_step=mfa.last_used_step)
        if step is not None:
            mfa.last_used_step = step
            mfa.save(using=_db(), update_fields=["last_used_step", "updated_at"])
            return True
        digest = _hash_recovery_code(_normalize_recovery_code(code))
        for stored in mfa.recovery_code_hashes:
            if hmac.compare_digest(stored, digest):
                mfa.recovery_code_hashes = [
                    value for value in mfa.recovery_code_hashes if value != stored
                ]
                mfa.save(
                    using=_db(), update_fields=["recovery_code_hashes", "updated_at"]
                )
                return True
    return False


def _require_second_factor(user, code: str) -> None:
    if not verify_second_factor(user.pk, code):
        raise MfaError(CODE_INVALID, "That code did not match. Enter a current code.")


def regenerate_recovery_codes(user, code: str) -> list[str]:
    _require_second_factor(user, code)
    mfa = get_user_mfa(user.pk)
    codes = new_recovery_codes()
    _store_recovery_codes(mfa, codes)
    mfa.save(using=_db(), update_fields=["recovery_code_hashes", "updated_at"])
    return codes


def disable(user, tenant_id, code: str) -> None:
    if tenant_requires_mfa(tenant_id):
        raise MfaError(
            "mfa_required_by_organization",
            "Your organization requires MFA, so it cannot be turned off.",
        )
    _require_second_factor(user, code)
    _user_mfa_model().objects.using(_db()).filter(user_id=user.pk).delete()
    _forget_enrolment(user_id=user.pk)


# --- Tenant policy ------------------------------------------------------------


def set_tenant_policy(tenant_id, user, require: bool) -> bool:
    """Turn the tenant requirement on or off. The admin must be enrolled first."""
    if require and is_password_user(user) and not is_enabled(user.pk):
        raise MfaError(
            "mfa_enrol_first",
            "Turn on MFA for your own account before requiring it for everyone.",
        )
    policy, _ = (
        _policy_model()
        .objects.using(_db())
        .get_or_create(tenant_id=tenant_id, defaults={"require_mfa": require})
    )
    policy.require_mfa = require
    policy.updated_by = user.pk
    policy.save(using=_db())
    _forget_enrolment(tenant_id=tenant_id)
    return policy.require_mfa
