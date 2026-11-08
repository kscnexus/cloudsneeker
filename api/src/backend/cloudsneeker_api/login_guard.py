"""Per-account sign-in lockout for ``POST /api/v1/tokens``.

Upstream only offers DRF's ``token-obtain`` scope, which keys on the client
IP. Sign-in reaches the API from the web app's server, so every user shares
a handful of hosting IPs and an IP limit would lock everyone out at once.
This guard counts failed sign-ins per email address instead:

* each 401 from the token endpoint (wrong password, or a wrong MFA code from
  ``MfaMiddleware``) adds one failure for that email;
* once an email has ``CLOUDSNEEKER_LOGIN_MAX_FAILURES`` failures inside
  ``CLOUDSNEEKER_LOGIN_LOCKOUT_SECONDS``, every sign-in for it answers 429
  ``sign_in_locked`` until the window ends, even with the right password,
  and no tokens are returned;
* a successful sign-in clears the count.

The body is read after the view, like the MFA and audit middleware, because
upstream views expect ``request.stream`` unread. Counters live in the
``cloudsneeker-shared`` cache (Valkey) so every API worker sees the same
count. When the cache is down the guard fails open and logs it: sign-in
availability beats the lockout.
"""

from __future__ import annotations

import hashlib
import logging

from cloudsneeker_api.mfa import token_attributes
from cloudsneeker_api.subscriptions import api_path
from config.env import env
from django.conf import settings
from django.http import JsonResponse

logger = logging.getLogger(__name__)

TOKEN_PATH = "tokens"
CACHE_ALIAS = "cloudsneeker-shared"
CODE_LOCKED = "sign_in_locked"
JSONAPI_CONTENT_TYPE = "application/vnd.api+json"
LOGIN_EMAIL_ATTRIBUTE = "cloudsneeker_sign_in_email"


def max_failures() -> int:
    return env.int("CLOUDSNEEKER_LOGIN_MAX_FAILURES", default=10)


def lockout_seconds() -> int:
    return env.int("CLOUDSNEEKER_LOGIN_LOCKOUT_SECONDS", default=900)


def enabled() -> bool:
    return bool(getattr(settings, "CLOUDSNEEKER_LOGIN_GUARD_ENABLED", True))


def _cache():
    from django.core.cache import caches
    from django.core.cache.backends.base import InvalidCacheBackendError

    try:
        return caches[CACHE_ALIAS]
    except InvalidCacheBackendError:
        return caches["default"]


def account_key(email: str) -> str:
    digest = hashlib.sha256(email.strip().lower().encode()).hexdigest()[:40]
    return f"cloudsneeker:login-failures:{digest}"


def failures(email: str) -> int:
    return int(_cache().get(account_key(email)) or 0)


def record_failure(email: str) -> int:
    cache = _cache()
    key = account_key(email)
    # The window starts at the first failure and is not extended by later ones.
    cache.add(key, 0, timeout=lockout_seconds())
    try:
        return cache.incr(key)
    except ValueError:
        cache.set(key, 1, timeout=lockout_seconds())
        return 1


def clear_failures(email: str) -> None:
    _cache().delete(account_key(email))


def is_locked(email: str) -> bool:
    return failures(email) >= max_failures()


def locked_response() -> JsonResponse:
    seconds = lockout_seconds()
    response = JsonResponse(
        {
            "errors": [
                {
                    "status": "429",
                    "code": CODE_LOCKED,
                    "title": "Too many failed sign-in attempts",
                    "detail": "This account is temporarily locked. "
                    f"Try again in {max(1, seconds // 60)} minutes.",
                }
            ]
        },
        status=429,
        content_type=JSONAPI_CONTENT_TYPE,
    )
    response["Retry-After"] = str(seconds)
    return response


def sign_in_email(request, response) -> str:
    """The email the client signed in with, or ``""``."""
    email = getattr(request, LOGIN_EMAIL_ATTRIBUTE, "") or ""
    if not email:
        email = str(token_attributes(request, response).get("email") or "")
    return email.strip()


def guard_token_response(request, response):
    email = sign_in_email(request, response)
    if not email:
        return response
    if is_locked(email):
        return locked_response()
    status_code = getattr(response, "status_code", 0)
    if status_code == 401:
        if record_failure(email) >= max_failures():
            logger.warning("Sign-in locked after repeated failures")
    elif status_code == 200:
        clear_failures(email)
    return response


class LoginGuardMiddleware:
    """Registered in ``config/django/base.py`` (``cloudsneeker-hook``) before
    ``MfaMiddleware``, so wrong MFA codes count as failures too."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (
            request.method != "POST"
            or api_path(request) != TOKEN_PATH
            or not enabled()
        ):
            return self.get_response(request)
        response = self.get_response(request)
        try:
            return guard_token_response(request, response)
        except Exception:
            logger.exception("Sign-in lockout check failed; allowing the request")
            return response
