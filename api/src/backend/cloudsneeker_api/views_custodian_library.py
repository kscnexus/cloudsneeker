"""Governance policy library and Seeker AI drafting endpoints."""

from api.base_views import BaseRLSViewSet
from api.db_utils import rls_transaction
from api.models import Provider
from api.rbac.permissions import Permissions
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX, CustodianPolicy
from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.serializers_custodian import (
    CustodianGenerateSerializer,
    CustodianLibraryInstallSerializer,
    CustodianValidateSerializer,
)
from cloudsneeker_api.services.custodian_ai import (
    PolicyGenerationError,
    generate_policy_draft,
    validate_draft,
)
from cloudsneeker_api.services.custodian_library import (
    LIBRARY_CATEGORIES,
    LIBRARY_PROVIDERS,
    get_library_policy,
    library_categories,
    library_coverage,
    library_policy_ids_in_yaml,
    list_library_policies,
)
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.parsers import JSONParser
from rest_framework.response import Response

LIBRARY_TYPE = f"{JSON_API_TYPE_PREFIX}custodian-library-policies"
DRAFT_TYPE = f"{JSON_API_TYPE_PREFIX}custodian-policy-drafts"
VALIDATION_TYPE = f"{JSON_API_TYPE_PREFIX}custodian-policy-validations"
POLICY_TYPE = f"{JSON_API_TYPE_PREFIX}custodian-policies"


def _attributes(request) -> dict:
    payload = request.data
    if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
        return payload["data"].get("attributes", {})
    return payload


@extend_schema_view(
    list=extend_schema(
        tags=["Custodian"],
        summary="List governance library policies",
        responses=OpenApiTypes.OBJECT,
    ),
)
class CustodianLibraryViewSet(BaseRLSViewSet):
    """Browse the built-in policy library, add policies, and draft with Seeker AI."""

    queryset = CustodianPolicy.objects.all()
    http_method_names = ["get", "post", "head", "options"]
    required_permissions = [Permissions.MANAGE_SCANS]
    # Documents are built by hand; skip JSON:API re-wrapping.
    resource_name = False
    pagination_class = None

    def get_queryset(self):
        return CustodianPolicy.objects.filter(tenant_id=self.request.tenant_id)

    def _workspace_policies(self) -> list[tuple[str, str]]:
        return list(
            self.get_queryset().values_list("provider__provider", "policy_yaml")
        )

    def list(self, request, *args, **kwargs):
        params = request.query_params
        provider_type = params.get("provider_type") or None
        if provider_type and provider_type not in LIBRARY_PROVIDERS:
            provider_type = None
        category = params.get("category") or None
        if category and category not in LIBRARY_CATEGORIES:
            category = None
        entries = list_library_policies(
            provider_type=provider_type,
            category=category,
            search=params.get("search"),
            starter_only=params.get("starter") in ("1", "true", "yes"),
        )
        coverage = library_coverage(
            self._workspace_policies(), provider_type=provider_type
        )
        installed = set(coverage["installed_ids"])
        return Response(
            {
                "data": [
                    {
                        "type": LIBRARY_TYPE,
                        "id": entry["id"],
                        "attributes": {**entry, "installed": entry["id"] in installed},
                    }
                    for entry in entries
                ],
                "meta": {
                    "count": len(entries),
                    "categories": library_categories(),
                    "coverage": coverage["categories"],
                },
            }
        )

    @extend_schema(
        tags=["Custodian"],
        summary="Add library policies to a provider",
        request=CustodianLibraryInstallSerializer,
        responses=OpenApiTypes.OBJECT,
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="install",
        parser_classes=[LenientJSONAPIParser, JSONParser],
    )
    def install(self, request):
        """Create dry-run policies from library entries for one provider."""
        serializer = CustodianLibraryInstallSerializer(data=_attributes(request))
        serializer.is_valid(raise_exception=True)
        provider = Provider.objects.filter(
            tenant_id=request.tenant_id, id=serializer.validated_data["provider_id"]
        ).first()
        if provider is None:
            return _error("Unknown provider ID for this tenant.")

        entries = []
        for policy_id in dict.fromkeys(serializer.validated_data["policy_ids"]):
            entry = get_library_policy(policy_id)
            if entry is None:
                return _error(f"Unknown library policy {policy_id!r}.")
            if entry["provider_type"] != provider.provider:
                return _error(
                    f"Library policy {policy_id!r} is for "
                    f"{entry['provider_type'].upper()}, not this provider."
                )
            entries.append(entry)

        created = []
        skipped = []
        provider_label = provider.alias or provider.uid
        with rls_transaction(str(request.tenant_id)):
            taken = set(
                CustodianPolicy.objects.filter(tenant_id=request.tenant_id).values_list(
                    "name", flat=True
                )
            )
            on_provider = {
                name
                for policy_yaml in CustodianPolicy.objects.filter(
                    tenant_id=request.tenant_id, provider=provider
                ).values_list("policy_yaml", flat=True)
                for name in library_policy_ids_in_yaml(policy_yaml)
            }
            for entry in entries:
                if entry["id"] in on_provider:
                    skipped.append(entry["id"])
                    continue
                name = entry["name"][:100]
                if name in taken:
                    name = f"{entry['name']} ({provider_label})"[:100]
                if name in taken:
                    skipped.append(entry["id"])
                    continue
                policy = CustodianPolicy.objects.create(
                    tenant_id=request.tenant_id,
                    name=name,
                    description=entry["description"],
                    policy_yaml=entry["policy_yaml"],
                    provider=provider,
                )
                taken.add(name)
                created.append(policy)

        return Response(
            {
                "data": [
                    {
                        "type": POLICY_TYPE,
                        "id": str(policy.id),
                        "attributes": {"name": policy.name},
                    }
                    for policy in created
                ],
                "meta": {"created": len(created), "skipped": skipped},
            },
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(
        tags=["Custodian"],
        summary="Draft a policy with Seeker AI",
        request=CustodianGenerateSerializer,
        responses=OpenApiTypes.OBJECT,
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="generate",
        parser_classes=[LenientJSONAPIParser, JSONParser],
    )
    def generate(self, request):
        """Draft and validate a dry-run policy from a plain-language request."""
        serializer = CustodianGenerateSerializer(data=_attributes(request))
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            draft = generate_policy_draft(
                tenant_id=str(request.tenant_id),
                provider_type=data["provider_type"],
                prompt=data["prompt"],
                resource_type=data.get("resource_type", ""),
            )
        except PolicyGenerationError as exc:
            # 424, not 5xx: the UI shows a 4xx detail but masks 5xx errors.
            return Response(
                {"errors": [{"detail": str(exc), "code": exc.code}]},
                status=(
                    status.HTTP_400_BAD_REQUEST
                    if exc.code == "llm_not_configured"
                    else status.HTTP_424_FAILED_DEPENDENCY
                ),
            )
        return Response({"data": {"type": DRAFT_TYPE, "id": "draft", "attributes": draft}})

    @extend_schema(
        tags=["Custodian"],
        summary="Validate governance policy YAML",
        request=CustodianValidateSerializer,
        responses=OpenApiTypes.OBJECT,
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="validate",
        parser_classes=[LenientJSONAPIParser, JSONParser],
    )
    def validate_policy(self, request):
        """Run the same checks a saved policy goes through."""
        serializer = CustodianValidateSerializer(data=_attributes(request))
        serializer.is_valid(raise_exception=True)
        error = validate_draft(
            serializer.validated_data["policy_yaml"],
            serializer.validated_data["provider_type"],
        )
        return Response(
            {
                "data": {
                    "type": VALIDATION_TYPE,
                    "id": "validation",
                    "attributes": {"valid": not error, "error": error},
                }
            }
        )


def _error(detail: str) -> Response:
    return Response(
        {"errors": [{"detail": detail}]}, status=status.HTTP_400_BAD_REQUEST
    )
