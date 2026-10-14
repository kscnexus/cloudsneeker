"""Slack OAuth and channel listing endpoints matching the UI contract."""

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from api.db_utils import rls_transaction
from api.models import Integration
from api.rbac.permissions import Permissions, get_role, roles_have_permissions
from cloudsneeker_api.services.slack import (
    build_authorize_url,
    exchange_oauth_code,
    list_channels,
    public_configuration,
    slack_app_configured,
)
from django.shortcuts import get_object_or_404
from rest_framework import permissions, status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView


def _tenant_id(request) -> str:
    """Read tenant from JWT/API-key auth.

    Plain ``APIView`` does not run ``BaseRLSViewSet.initial``, so
    ``request.tenant_id`` is never set. Auth payloads carry ``tenant_id``.
    """
    tenant_id = request.auth.get("tenant_id") if request.auth else None
    if not tenant_id:
        raise PermissionDenied("Tenant context is required.")
    return str(tenant_id)


def _require_manage_integrations(request) -> str:
    tenant_id = _tenant_id(request)
    role = get_role(request.user, tenant_id)
    roles = [role] if role else []
    if not roles_have_permissions(roles, [Permissions.MANAGE_INTEGRATIONS]):
        raise PermissionDenied("You do not have permission to manage integrations.")
    return tenant_id


def _integration_document(integration: Integration) -> dict:
    return {
        "id": str(integration.id),
        "type": "integrations",
        "attributes": {
            "inserted_at": integration.inserted_at.isoformat().replace("+00:00", "Z"),
            "updated_at": integration.updated_at.isoformat().replace("+00:00", "Z"),
            "enabled": integration.enabled,
            "connected": integration.connected,
            "connection_last_checked_at": (
                integration.connection_last_checked_at.isoformat().replace(
                    "+00:00", "Z"
                )
                if integration.connection_last_checked_at
                else None
            ),
            "integration_type": integration.integration_type,
            "configuration": public_configuration(integration.configuration or {}),
        },
    }


def _error_response(message: str, status_code: int, code: str | None = None, headers=None):
    body = {
        "errors": [
            {
                "status": str(status_code),
                "detail": message,
                "source": {"pointer": "/data"},
            }
        ]
    }
    if code:
        body["errors"][0]["code"] = code
    return Response(body, status=status_code, headers=headers or {})


class SlackOAuthAuthorizeUrlView(APIView):
    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        tenant_id = _require_manage_integrations(request)
        if not slack_app_configured(tenant_id):
            return _error_response(
                "Slack is not configured for this tenant.",
                status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        try:
            authorize_url = build_authorize_url(
                tenant_id=tenant_id,
                user_id=str(request.user.id),
            )
        except ValidationError as exc:
            detail = exc.detail
            message = detail.get("detail") if isinstance(detail, dict) else str(detail)
            return _error_response(str(message), status.HTTP_400_BAD_REQUEST)
        return Response({"meta": {"authorize_url": authorize_url}})


class SlackOAuthExchangeView(APIView):
    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        tenant_id = _require_manage_integrations(request)
        if not slack_app_configured(tenant_id):
            return _error_response(
                "Slack is not configured for this tenant.",
                status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        payload = request.data or {}
        if isinstance(payload.get("data"), dict):
            attributes = payload["data"].get("attributes") or {}
        else:
            attributes = payload.get("attributes") or payload
        code = attributes.get("code") or ""
        state = attributes.get("state") or ""
        if not code or not state:
            return _error_response(
                "code and state are required.", status.HTTP_400_BAD_REQUEST
            )

        try:
            integration = exchange_oauth_code(
                tenant_id=tenant_id,
                user_id=str(request.user.id),
                code=code,
                state=state,
            )
        except ValidationError as exc:
            detail = (
                exc.detail if isinstance(exc.detail, dict) else {"detail": str(exc.detail)}
            )
            message = detail.get("detail") or "Unable to complete Slack OAuth."
            code_name = detail.get("code")
            status_code = status.HTTP_400_BAD_REQUEST
            if code_name == "workspace_conflict":
                status_code = status.HTTP_409_CONFLICT
            elif code_name == "slack_upstream":
                status_code = status.HTTP_502_BAD_GATEWAY
            return _error_response(str(message), status_code, code=code_name)

        created = integration.inserted_at == integration.updated_at
        return Response(
            {"data": _integration_document(integration)},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class SlackChannelsView(APIView):
    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, integration_id, *args, **kwargs):
        tenant_id = _require_manage_integrations(request)
        with rls_transaction(tenant_id):
            integration = get_object_or_404(
                Integration.objects.filter(
                    tenant_id=tenant_id,
                    integration_type=Integration.IntegrationChoices.SLACK,
                ),
                pk=integration_id,
            )

        cursor = request.query_params.get("page[cursor]") or None
        try:
            channels, next_cursor = list_channels(integration, cursor=cursor)
        except ValidationError as exc:
            detail = (
                exc.detail if isinstance(exc.detail, dict) else {"detail": str(exc.detail)}
            )
            message = detail.get("detail") or "Unable to list Slack channels."
            code_name = detail.get("code")
            status_code = status.HTTP_400_BAD_REQUEST
            headers = {}
            if code_name == "rate_limited":
                status_code = status.HTTP_429_TOO_MANY_REQUESTS
                retry_after = detail.get("retry_after")
                if retry_after:
                    headers["Retry-After"] = str(retry_after)
            elif code_name == "slack_upstream":
                status_code = status.HTTP_502_BAD_GATEWAY
            return _error_response(
                str(message), status_code, code=code_name, headers=headers
            )

        next_link = None
        if next_cursor:
            next_link = (
                f"{request.build_absolute_uri(request.path)}"
                f"?page%5Bcursor%5D={next_cursor}"
            )

        return Response(
            {
                "data": [
                    {
                        "type": "slack-channels",
                        "id": channel["id"],
                        "attributes": {
                            "name": channel["name"],
                            "is_private": channel["is_private"],
                        },
                    }
                    for channel in channels
                ],
                "links": {"next": next_link},
            }
        )
