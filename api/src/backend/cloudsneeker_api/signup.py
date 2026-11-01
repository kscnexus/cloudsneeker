"""Switch to close self sign-up (EB-002).

``SignupGateMiddleware`` refuses ``POST /api/v1/users`` without an
``invitation_token`` query parameter when
``CLOUDSNEEKER_SELF_REGISTRATION_ENABLED`` is ``"false"``. The upstream view
still validates the token, so an invalid or expired invitation fails there.

Sign-up stays open while the database has no users, so a new install can
create its first owner. Unset or any other value keeps upstream behavior
(open sign-up). The hosted stack sets it to ``"false"`` in ``platform.yaml``.
"""

from __future__ import annotations

import logging
import os

from cloudsneeker_api.subscriptions import api_path, error_response

logger = logging.getLogger(__name__)

ENV_VAR = "CLOUDSNEEKER_SELF_REGISTRATION_ENABLED"
CODE_SIGNUP_CLOSED = "signup_closed"


def self_registration_enabled() -> bool:
    """On unless the env var is ``"false"`` (same rule as the UI flag)."""
    return os.environ.get(ENV_VAR, "").strip().lower() != "false"


def _has_users() -> bool:
    from api.db_router import MainRouter
    from api.models import User

    return User.objects.using(MainRouter.admin_db).exists()


def is_closed_signup_request(request) -> bool:
    """``True`` when this request is a sign-up the switch refuses."""
    if request.method != "POST" or api_path(request) != "users":
        return False
    if request.GET.get("invitation_token"):
        return False
    if self_registration_enabled():
        return False
    return _has_users()


class SignupGateMiddleware:
    """Refuse uninvited sign-ups while self sign-up is closed.

    Registered in ``config/django/base.py`` (``cloudsneeker-hook``).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            closed = is_closed_signup_request(request)
        except Exception:
            # Fail closed: a sign-up that cannot be checked is not let through.
            logger.exception("Sign-up gate failed for %s", request.path)
            closed = not self_registration_enabled()
        if closed:
            return error_response(
                CODE_SIGNUP_CLOSED,
                "Sign-up is closed",
                "Accounts are created by invitation. Ask an administrator "
                "of your organization to invite you.",
            )
        return self.get_response(request)
