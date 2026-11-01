"""SAML options per organization (EB-009).

``GET`` / ``PATCH /sso/policy`` (``reject_idp_initiated_sso``): whether SAML
sign-ins must start on this site. Changing it needs the ``manage_account``
permission. Signing and signature checks are always on (``saml.py``).
"""

from __future__ import annotations

from api.db_router import MainRouter
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX, TenantSsoPolicy
from cloudsneeker_api.saml import rejects_idp_initiated, sp_key_pair
from cloudsneeker_api.views_mfa import (
    _can_manage_account,
    _error,
    _MfaView,
    _resource,
    _tenant_id,
)
from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.response import Response

TYPE_SSO_POLICY = f"{JSON_API_TYPE_PREFIX}sso-policies"


def _attributes(tenant_id) -> dict:
    return {
        "reject_idp_initiated_sso": rejects_idp_initiated(tenant_id),
        "signed_requests": sp_key_pair() is not None,
        "signed_assertions_required": True,
    }


@extend_schema(exclude=True)
class SsoPolicyView(_MfaView):
    def get(self, request):
        tenant_id = _tenant_id(request)
        return Response(_resource(TYPE_SSO_POLICY, tenant_id, _attributes(tenant_id)))

    def patch(self, request):
        tenant_id = _tenant_id(request)
        if not tenant_id or not _can_manage_account(request.user, tenant_id):
            return _error(
                "Changing single sign-on options needs the manage account permission.",
                "permission_denied",
                status.HTTP_403_FORBIDDEN,
            )
        data = request.data if isinstance(request.data, dict) else {}
        reject = data.get("reject_idp_initiated_sso")
        if not isinstance(reject, bool):
            return _error(
                "reject_idp_initiated_sso must be true or false.",
                "invalid",
                status.HTTP_400_BAD_REQUEST,
            )
        TenantSsoPolicy.objects.using(MainRouter.admin_db).update_or_create(
            tenant_id=tenant_id,
            defaults={
                "reject_idp_initiated_sso": reject,
                "updated_by": request.user.pk,
            },
        )
        return Response(_resource(TYPE_SSO_POLICY, tenant_id, _attributes(tenant_id)))
