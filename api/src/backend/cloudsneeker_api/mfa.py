"""MFA enforcement around upstream views (EB-008).

``MfaMiddleware`` does two things without editing an upstream view:

* ``POST /api/v1/tokens``: when the password was right (the view answered
  200) and the user has MFA on, the tokens are only returned with a valid
  ``otp_code`` attribute (an authenticator code or a recovery code).
  Otherwise the answer becomes 401 ``mfa_required`` or ``mfa_invalid`` and
  the issued tokens are dropped.
* Every other bearer-token request: when the tenant requires MFA and this
  password user has not enrolled, only MFA setup and a few session reads are
  allowed; the rest gets 403 ``mfa_enrolment_required``.

API keys, SAML and social sign-in are never asked for a code. The token body
is read after the view, from DRF's parsed data, like the audit middleware.
"""

from __future__ import annotations

import logging

from cloudsneeker_api.audit import read_json_body
from cloudsneeker_api.services import mfa as service
from cloudsneeker_api.subscriptions import api_path, request_identity
from django.http import JsonResponse

logger = logging.getLogger(__name__)

JSONAPI_CONTENT_TYPE = "application/vnd.api+json"
TOKEN_PATH = "tokens"
OTP_ATTRIBUTE = "otp_code"

CODE_MFA_REQUIRED = "mfa_required"
CODE_MFA_INVALID = "mfa_invalid"
CODE_MFA_ENROLMENT_REQUIRED = "mfa_enrolment_required"

# Reachable while enrolment is required (any method).
ENROLMENT_OPEN_PREFIXES = ("tokens", "mfa", "schema", "docs")
# Session reads the app shell makes on every page.
ENROLMENT_OPEN_READS = frozenset(
    {"users/me", "entitlements", "operator/me", "cloudsneeker/brand", "tenants"}
)


def _error(status: int, code: str, title: str, detail: str) -> JsonResponse:
    return JsonResponse(
        {
            "errors": [
                {"status": str(status), "code": code, "title": title, "detail": detail}
            ]
        },
        status=status,
        content_type=JSONAPI_CONTENT_TYPE,
    )


def _open_while_enrolling(path: str, method: str) -> bool:
    for prefix in ENROLMENT_OPEN_PREFIXES:
        if path == prefix or path.startswith(f"{prefix}/"):
            return True
    return method in ("GET", "HEAD", "OPTIONS") and path in ENROLMENT_OPEN_READS


def token_attributes(request, response) -> dict:
    data = read_json_body(request, response)
    if not isinstance(data, dict):
        return {}
    # Plain JSON clients send the JSON:API envelope unparsed.
    resource = data.get("data")
    if isinstance(resource, dict) and isinstance(resource.get("attributes"), dict):
        return resource["attributes"]
    return data


def gate_token_response(request, response):
    """The token response, or a 401 when the second factor is missing or wrong."""
    if getattr(response, "status_code", 0) != 200:
        return response
    attributes = token_attributes(request, response)
    email = str(attributes.get("email") or "").strip()
    if not email:
        return response

    from api.db_router import MainRouter
    from api.models import User

    user = User.objects.using(MainRouter.admin_db).filter(email__iexact=email).first()
    if user is None or not service.is_enabled(user.pk):
        return response
    if not service.is_password_user(user):
        return response

    code = attributes.get(OTP_ATTRIBUTE)
    if not code:
        return _error(
            401,
            CODE_MFA_REQUIRED,
            "Verification code required",
            "Enter the code from your authenticator app, or a recovery code.",
        )
    if not service.verify_second_factor(user.pk, str(code)):
        return _error(
            401,
            CODE_MFA_INVALID,
            "Verification code did not match",
            "Enter a current code from your authenticator app, or an unused "
            "recovery code.",
        )
    return response


def enrolment_denial(request, path: str):
    """403 when the tenant requires MFA and this user has not enrolled."""
    if _open_while_enrolling(path, request.method):
        return None
    identity = request_identity(request)
    if identity is None or identity.api_key or not identity.user_id:
        return None
    if not service.enrolment_required(identity.user_id, identity.tenant_id):
        return None
    return _error(
        403,
        CODE_MFA_ENROLMENT_REQUIRED,
        "Set up multi-factor authentication",
        "Your organization requires MFA. Add an authenticator app under "
        "Settings > Security to continue.",
    )


class MfaMiddleware:
    """Registered in ``config/django/base.py`` (``cloudsneeker-hook``)."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = api_path(request)
        if path is None:
            return self.get_response(request)

        if request.method == "POST" and path == TOKEN_PATH:
            response = self.get_response(request)
            try:
                return gate_token_response(request, response)
            except Exception:
                # Fail closed: never hand out tokens the check could not clear.
                logger.exception("MFA check failed on sign-in")
                return _error(
                    503,
                    "mfa_unavailable",
                    "Sign-in temporarily unavailable",
                    "Try again in a moment.",
                )

        try:
            denial = enrolment_denial(request, path)
        except Exception:
            logger.exception("MFA enrolment check failed for %s", request.path)
            denial = None
        if denial is not None:
            return denial
        return self.get_response(request)
