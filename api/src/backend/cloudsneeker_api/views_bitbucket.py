"""Bitbucket workspace import: list the repositories a token can read.

``POST /api/v1/bitbucket/repositories`` takes the token in the body (never
the query string) and returns each repository with ``already_added`` set when
the tenant has an IaC provider for it. Creating providers stays on the
existing ``/providers`` and ``/providers/secrets`` endpoints.
"""

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from api.db_utils import rls_transaction
from api.models import Provider
from api.rbac.permissions import Permissions, get_role, roles_have_permissions
from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.services.bitbucket import (
    CODE_NOT_FOUND,
    CODE_UNREACHABLE,
    BitbucketError,
    list_repositories,
    normalize_repository_url,
)
from cloudsneeker_api.views import JSONAPIDocumentRenderer
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, status
from rest_framework.exceptions import PermissionDenied
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView

RESOURCE_TYPE = "bitbucket-repositories"

ERROR_STATUS = {
    CODE_NOT_FOUND: status.HTTP_404_NOT_FOUND,
    CODE_UNREACHABLE: status.HTTP_502_BAD_GATEWAY,
}


def _require_manage_providers(request) -> str:
    """Return the tenant from the auth payload after checking the role.

    Plain ``APIView`` does not set ``request.tenant_id``.
    """
    tenant_id = request.auth.get("tenant_id") if request.auth else None
    if not tenant_id:
        raise PermissionDenied("Tenant context is required.")
    role = get_role(request.user, str(tenant_id))
    if not roles_have_permissions(
        [role] if role else [], [Permissions.MANAGE_PROVIDERS]
    ):
        raise PermissionDenied("You do not have permission to manage providers.")
    return str(tenant_id)


def _added_repository_keys(tenant_id: str) -> set[str]:
    with rls_transaction(tenant_id):
        uids = Provider.objects.filter(
            tenant_id=tenant_id, provider=Provider.ProviderChoices.IAC
        ).values_list("uid", flat=True)
        return {normalize_repository_url(uid) for uid in uids}


def _error_response(error: BitbucketError) -> Response:
    status_code = ERROR_STATUS.get(error.code, status.HTTP_400_BAD_REQUEST)
    return Response(
        {
            "errors": [
                {
                    "status": str(status_code),
                    "code": error.code,
                    "detail": str(error),
                    "source": {"pointer": "/data/attributes"},
                }
            ]
        },
        status=status_code,
    )


class BitbucketRepositoriesView(APIView):
    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [LenientJSONAPIParser, JSONParser]
    # The document is built here; the default renderer would wrap it again.
    renderer_classes = [JSONAPIDocumentRenderer]

    @extend_schema(
        tags=["Bitbucket"], summary="List repositories in a Bitbucket workspace"
    )
    def post(self, request, *args, **kwargs):
        tenant_id = _require_manage_providers(request)
        attributes = request.data if isinstance(request.data, dict) else {}
        if isinstance(attributes.get("data"), dict):
            attributes = attributes["data"].get("attributes") or {}

        try:
            listing = list_repositories(
                access_token=str(attributes.get("access_token") or ""),
                workspace=str(attributes.get("workspace") or ""),
                username=str(attributes.get("username") or ""),
                server_url=str(attributes.get("server_url") or ""),
            )
        except BitbucketError as error:
            return _error_response(error)

        added = _added_repository_keys(tenant_id)
        data = [
            {
                "type": RESOURCE_TYPE,
                "id": repository.repository_url,
                "attributes": {
                    **repository.to_dict(),
                    "already_added": bool(
                        {
                            normalize_repository_url(repository.repository_url),
                            normalize_repository_url(repository.ssh_url),
                        }
                        & added
                    ),
                },
            }
            for repository in listing.repositories
        ]
        return Response(
            {
                "data": data,
                "meta": {
                    "count": len(data),
                    "clone_username": listing.clone_username,
                    "truncated": listing.truncated,
                },
            }
        )
