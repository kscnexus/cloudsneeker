"""GitHub repositories: list what a GitHub connection can read.

``GET /api/v1/github/providers/{id}/repositories`` returns the repositories
of a GitHub provider's account, each with ``already_added`` set when the
tenant has a repository source (IaC provider) for it. Creating the sources
stays on the existing ``/providers`` and ``/providers/secrets`` endpoints.
"""

from api.authentication import CombinedJWTOrAPIKeyAuthentication
from api.db_utils import rls_transaction
from api.models import Provider
from cloudsneeker_api.github_connection import GithubConnectionError
from cloudsneeker_api.services.bitbucket import normalize_repository_url
from cloudsneeker_api.services.github_repositories import list_repositories
from cloudsneeker_api.views import JSONAPIDocumentRenderer
from cloudsneeker_api.views_bitbucket import (
    _added_repository_keys,
    _require_manage_providers,
)
from drf_spectacular.utils import extend_schema
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

RESOURCE_TYPE = "github-repositories"


def _error(status_code: int, code: str, detail: str) -> Response:
    return Response(
        {"errors": [{"status": str(status_code), "code": code, "detail": detail}]},
        status=status_code,
    )


class GithubRepositoriesView(APIView):
    authentication_classes = [CombinedJWTOrAPIKeyAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    # The document is built here; the default renderer would wrap it again.
    renderer_classes = [JSONAPIDocumentRenderer]

    @extend_schema(
        tags=["GitHub"], summary="List the repositories of a GitHub connection"
    )
    def get(self, request, pk, *args, **kwargs):
        tenant_id = _require_manage_providers(request)
        with rls_transaction(tenant_id):
            github_provider = (
                Provider.objects.filter(
                    tenant_id=tenant_id,
                    provider=Provider.ProviderChoices.GITHUB.value,
                    pk=pk,
                )
                .select_related("secret")
                .first()
            )
        if github_provider is None:
            return _error(
                status.HTTP_404_NOT_FOUND,
                "not_found",
                "No GitHub connection with this id.",
            )

        try:
            listing = list_repositories(github_provider)
        except GithubConnectionError as error:
            return _error(
                status.HTTP_400_BAD_REQUEST, "github_connection_failed", str(error)
            )

        added = _added_repository_keys(tenant_id)
        data = [
            {
                "type": RESOURCE_TYPE,
                "id": repository.repository_url,
                "attributes": {
                    **repository.to_dict(),
                    "already_added": normalize_repository_url(repository.repository_url)
                    in added,
                },
            }
            for repository in listing.repositories
        ]
        return Response(
            {"data": data, "meta": {"count": len(data), "truncated": listing.truncated}}
        )
