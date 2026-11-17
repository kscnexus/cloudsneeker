"""Git connections as the source of code repositories.

``/appsec-source-connections`` lists the GitHub providers (connections) with
the repositories imported from each. A connection's repositories can be
listed and imported as code repository sources without entering the token
again (``services/github_source.py``).
"""

from __future__ import annotations

from uuid import UUID

from api.models import Provider
from api.rbac.permissions import Permissions
from cloudsneeker_api.models import RepositoryConnection
from cloudsneeker_api.services.github_source import (
    CODE_INVALID,
    CODE_NO_CREDENTIALS,
    CODE_NOT_GITHUB,
    CODE_UNAUTHORIZED,
    GitHubSourceError,
    import_repositories,
    list_repositories,
    normalize_url,
)
from cloudsneeker_api.views_appsec import AppSecViewSet
from django.db.models import Count
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.response import Response

TYPE = "cloudsneeker-appsec-source-connections"
REPOSITORY_TYPE = "cloudsneeker-appsec-source-repositories"

ERROR_STATUS = {
    CODE_INVALID: status.HTTP_400_BAD_REQUEST,
    CODE_NOT_GITHUB: status.HTTP_404_NOT_FOUND,
    CODE_NO_CREDENTIALS: status.HTTP_400_BAD_REQUEST,
    CODE_UNAUTHORIZED: status.HTTP_400_BAD_REQUEST,
}


def _error(error: GitHubSourceError) -> Response:
    code = ERROR_STATUS.get(error.code, status.HTTP_502_BAD_GATEWAY)
    # The JSON:API renderer wraps error responses in ``{"errors": ...}``.
    return Response(
        [{"status": str(code), "code": error.code, "detail": str(error)}], status=code
    )


class AppSecSourceConnectionViewSet(AppSecViewSet):
    """GitHub connections and the repositories imported from them."""

    def set_required_permissions(self):
        # Listing a connection's repositories uses its credentials, and the
        # import creates providers: both need provider management.
        self.required_permissions = (
            [] if self.action == "list" else [Permissions.MANAGE_PROVIDERS]
        )

    def _connections(self):
        queryset = Provider.objects.filter(
            tenant_id=self.tenant_id, provider=Provider.ProviderChoices.GITHUB
        )
        if self.visible is not None:
            queryset = queryset.filter(id__in=list(self.visible))
        return queryset

    def _connection(self, pk) -> Provider:
        try:
            pk = UUID(str(pk))
        except ValueError:
            raise NotFound("Connection not found.") from None
        connection = self._connections().filter(id=pk).select_related("secret").first()
        if connection is None:
            raise NotFound("Connection not found.")
        return connection

    @extend_schema(
        tags=["AppSec"],
        summary="GitHub connections and their imported repositories",
        responses={200: OpenApiResponse(description="Connections")},
    )
    def list(self, request, *args, **kwargs):
        connections = list(
            self._connections()
            .annotate(repository_count=Count("cloudsneeker_connected_repositories"))
            .order_by("alias", "uid")
        )
        links = RepositoryConnection.objects.filter(
            tenant_id=self.tenant_id, connection__in=connections
        ).values_list("connection_id", "repository_id")
        repositories: dict[str, list[str]] = {}
        for connection_id, repository_id in links:
            repositories.setdefault(str(connection_id), []).append(str(repository_id))
        return Response(
            {
                "data": [
                    {
                        "type": TYPE,
                        "id": str(connection.id),
                        "attributes": {
                            "provider": connection.provider,
                            "uid": connection.uid,
                            "alias": connection.alias,
                            "repository_count": connection.repository_count,
                            "repository_ids": repositories.get(str(connection.id), []),
                        },
                    }
                    for connection in connections
                ]
            }
        )

    @extend_schema(
        tags=["AppSec"],
        summary="Repositories a GitHub connection can read",
        responses={200: OpenApiResponse(description="Repositories")},
    )
    @action(detail=True, methods=["get"], url_path="repositories")
    def repositories(self, request, pk=None):
        connection = self._connection(pk)
        try:
            listing = list_repositories(connection)
        except GitHubSourceError as error:
            return _error(error)
        added = {
            normalize_url(uid)
            for uid in Provider.objects.filter(
                tenant_id=self.tenant_id, provider=Provider.ProviderChoices.IAC
            ).values_list("uid", flat=True)
        }
        return Response(
            {
                "data": [
                    {
                        "type": REPOSITORY_TYPE,
                        "id": repository.clone_url,
                        "attributes": {
                            **repository.to_dict(),
                            "already_added": normalize_url(repository.clone_url)
                            in added,
                        },
                    }
                    for repository in listing
                ]
            }
        )

    @extend_schema(
        tags=["AppSec"],
        summary="Import repositories of a GitHub connection as code sources",
        responses={200: OpenApiResponse(description="Import result")},
    )
    @action(detail=True, methods=["post"], url_path="import")
    def import_repositories(self, request, pk=None):
        connection = self._connection(pk)
        urls = self.body.get("clone_urls")
        if not isinstance(urls, list) or not all(isinstance(url, str) for url in urls):
            raise ValidationError(
                {"clone_urls": "A list of repository URLs is required."}
            )
        try:
            result = import_repositories(
                tenant_id=self.tenant_id,
                connection_id=str(connection.id),
                clone_urls=urls,
            )
        except GitHubSourceError as error:
            return _error(error)
        return Response(
            {
                "data": {
                    "type": f"{TYPE}-imports",
                    "id": str(connection.id),
                    "attributes": result,
                }
            }
        )
