"""MFA API for the signed-in user and the tenant policy (EB-008).

* ``GET /mfa``: status for the current user and tenant.
* ``POST /mfa/enrolment``: start setup; returns the secret and otpauth URI.
* ``POST /mfa/enrolment/confirm`` (``code``): turn MFA on; returns recovery codes.
* ``POST /mfa/recovery-codes`` (``code``): replace the recovery codes.
* ``POST /mfa/disable`` (``code``): turn MFA off.
* ``GET`` / ``PATCH /mfa/policy`` (``require_mfa``): tenant requirement;
  changing it needs the ``manage_account`` permission.

Secrets and recovery codes are returned once and never logged.
"""

from __future__ import annotations

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from api.db_router import MainRouter
from api.models import UserRoleRelationship
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX
from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.services import mfa as service
from cloudsneeker_api.views import JSONAPIDocumentRenderer
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, status
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework.views import APIView

TYPE_MFA_STATUS = f"{JSON_API_TYPE_PREFIX}mfa-status"
TYPE_MFA_ENROLMENT = f"{JSON_API_TYPE_PREFIX}mfa-enrolments"
TYPE_MFA_RECOVERY_CODES = f"{JSON_API_TYPE_PREFIX}mfa-recovery-codes"
TYPE_MFA_POLICY = f"{JSON_API_TYPE_PREFIX}mfa-policies"


class MfaCodeThrottle(UserRateThrottle):
    """Limits code guesses on the endpoints that check one."""

    scope = "cloudsneeker-mfa-code"
    rate = "10/min"


def _resource(resource_type: str, resource_id, attributes: dict) -> dict:
    return {
        "data": {
            "type": resource_type,
            "id": str(resource_id),
            "attributes": attributes,
        }
    }


def _error(detail: str, code: str, http_status: int) -> Response:
    # The renderer is plain JSON: build the JSON:API error document here.
    return Response(
        {"errors": [{"detail": detail, "code": code, "status": str(http_status)}]},
        status=http_status,
    )


def _mfa_error(error: service.MfaError) -> Response:
    http_status = (
        status.HTTP_400_BAD_REQUEST
        if error.code == service.CODE_INVALID
        else status.HTTP_409_CONFLICT
    )
    return _error(error.detail, error.code, http_status)


def _tenant_id(request):
    auth = request.auth
    return auth.get("tenant_id") if hasattr(auth, "get") else None


def _is_api_key(request) -> bool:
    auth = request.auth
    return bool(hasattr(auth, "get") and auth.get("api_key_prefix"))


def _code(request) -> str:
    data = request.data if isinstance(request.data, dict) else {}
    return str(data.get("code") or "")


class _MfaView(APIView):
    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    renderer_classes = [JSONAPIDocumentRenderer]
    parser_classes = [LenientJSONAPIParser, JSONParser]

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if _is_api_key(request):
            # MFA belongs to people signing in, never to API keys.
            self.permission_denied(request, message="Use a signed-in session.")


@extend_schema(exclude=True)
class MfaStatusView(_MfaView):
    def get(self, request):
        return Response(
            _resource(
                TYPE_MFA_STATUS,
                request.user.pk,
                service.status(request.user, _tenant_id(request)),
            )
        )


@extend_schema(exclude=True)
class MfaEnrolmentView(_MfaView):
    def post(self, request):
        try:
            enrolment = service.begin_enrolment(request.user)
        except service.MfaError as error:
            return _mfa_error(error)
        return Response(
            _resource(TYPE_MFA_ENROLMENT, request.user.pk, enrolment),
            status=status.HTTP_201_CREATED,
        )


@extend_schema(exclude=True)
class MfaEnrolmentConfirmView(_MfaView):
    throttle_classes = [MfaCodeThrottle]

    def post(self, request):
        try:
            codes = service.confirm_enrolment(request.user, _code(request))
        except service.MfaError as error:
            return _mfa_error(error)
        return Response(
            _resource(TYPE_MFA_RECOVERY_CODES, request.user.pk, {"codes": codes})
        )


@extend_schema(exclude=True)
class MfaRecoveryCodesView(_MfaView):
    throttle_classes = [MfaCodeThrottle]

    def post(self, request):
        try:
            codes = service.regenerate_recovery_codes(request.user, _code(request))
        except service.MfaError as error:
            return _mfa_error(error)
        return Response(
            _resource(TYPE_MFA_RECOVERY_CODES, request.user.pk, {"codes": codes})
        )


@extend_schema(exclude=True)
class MfaDisableView(_MfaView):
    throttle_classes = [MfaCodeThrottle]

    def post(self, request):
        try:
            service.disable(request.user, _tenant_id(request), _code(request))
        except service.MfaError as error:
            return _mfa_error(error)
        return Response(status=status.HTTP_204_NO_CONTENT)


def _can_manage_account(user, tenant_id) -> bool:
    return (
        UserRoleRelationship.objects.using(MainRouter.admin_db)
        .filter(user_id=user.pk, tenant_id=tenant_id, role__manage_account=True)
        .exists()
    )


@extend_schema(exclude=True)
class MfaPolicyView(_MfaView):
    def get(self, request):
        tenant_id = _tenant_id(request)
        return Response(
            _resource(
                TYPE_MFA_POLICY,
                tenant_id,
                {"require_mfa": service.tenant_requires_mfa(tenant_id)},
            )
        )

    def patch(self, request):
        tenant_id = _tenant_id(request)
        if not tenant_id or not _can_manage_account(request.user, tenant_id):
            return _error(
                "Changing the MFA requirement needs the manage account permission.",
                "permission_denied",
                status.HTTP_403_FORBIDDEN,
            )
        data = request.data if isinstance(request.data, dict) else {}
        require = data.get("require_mfa")
        if not isinstance(require, bool):
            return _error(
                "require_mfa must be true or false.",
                "invalid",
                status.HTTP_400_BAD_REQUEST,
            )
        try:
            value = service.set_tenant_policy(tenant_id, request.user, require)
        except service.MfaError as error:
            return _mfa_error(error)
        return Response(_resource(TYPE_MFA_POLICY, tenant_id, {"require_mfa": value}))
