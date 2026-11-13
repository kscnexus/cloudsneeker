"""Application security posture management (ASPM) API.

All routes are under ``/api/v1/appsec-*`` and need the Application Security
plan feature (``subscriptions.FEATURE_PATH_PREFIXES``). Reading follows
provider visibility; every write needs ``manage_scans`` and is recorded by
the audit log middleware.

Responses are JSON:API shaped (``data`` with ``type``, ``id``,
``attributes``; ``meta.pagination``). Lists take ``page[number]``,
``page[size]`` (at most 100), ``filter[...]`` and ``sort``.

Triage (status, notes, assignee) is not here: it uses the existing
``findings/<uid>/triage`` and ``finding-triages`` routes with the finding's
``uid``.
"""

from __future__ import annotations

import csv
import io
import json
import math
from datetime import timedelta
from typing import Any
from uuid import UUID

from api.base_views import BaseRLSViewSet
from api.models import Provider
from api.rbac.permissions import Permissions
from cloudsneeker_api.appsec import capabilities as caps
from cloudsneeker_api.appsec import policies as policy_rules
from cloudsneeker_api.appsec import queries, sbom
from cloudsneeker_api.appsec.options import OptionError, validate_profile_options
from cloudsneeker_api.appsec.risk import (
    DEFAULT_RISK_CONFIG,
    DEFAULT_SLA_DAYS,
    RiskConfigError,
    merge_risk_config,
    merge_sla_days,
)
from cloudsneeker_api.models import (
    JSON_API_TYPE_PREFIX,
    AppSecApplication,
    AppSecComponent,
    AppSecFinding,
    AppSecFindingEvent,
    AppSecPolicy,
    AppSecPolicyVersion,
    AppSecSbom,
    AppSecScanProfile,
    AppSecSettings,
    FindingTriage,
    TrivyRun,
    TrivyTarget,
)
from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.reports.access import visible_provider_ids
from cloudsneeker_api.serializers_triage import FindingTriageSerializer
from cloudsneeker_api.services.brand_text import scrub_engine_text
from cloudsneeker_api.services.repo_branches import (
    RepositoryBranchError,
    list_repository_branches,
)
from django.db import transaction
from django.db.models import Count, Q
from django.http import HttpResponse
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.parsers import JSONParser
from rest_framework.permissions import SAFE_METHODS
from rest_framework.response import Response

TAG = "Application security"


def _type(name: str) -> str:
    return f"{JSON_API_TYPE_PREFIX}appsec-{name}"


def _iso(value) -> str | None:
    return value.isoformat() if value else None


def _uuid(value: Any, name: str = "id") -> UUID:
    try:
        return UUID(str(value))
    except (ValueError, TypeError):
        raise NotFound(f"Unknown {name}.") from None


def _text(
    data: dict, name: str, *, limit: int, required: bool = False, minimum: int = 0
):
    """Return a cleaned text attribute, or ``None`` when it is absent."""
    if name not in data:
        if required:
            raise ValidationError({name: "This field is required."})
        return None
    value = data[name]
    if not isinstance(value, str):
        raise ValidationError({name: "Must be text."})
    value = value.strip()
    if len(value) < minimum:
        raise ValidationError({name: f"Use at least {minimum} characters."})
    if len(value) > limit:
        raise ValidationError({name: f"Use at most {limit} characters."})
    return value


def _choice(data: dict, name: str, choices) -> str | None:
    if name not in data:
        return None
    allowed = [value for value, _ in choices]
    if data[name] not in allowed:
        raise ValidationError({name: f"Must be one of: {', '.join(allowed)}."})
    return data[name]


def _profile_ref(tenant_id, value: Any, name: str) -> str:
    """Validate a ``builtin:<key>`` or scan profile id; empty clears it."""
    ref = str(value or "").strip()
    if not ref:
        return ""
    if ref.startswith(caps.BUILTIN_PROFILE_PREFIX):
        if ref[len(caps.BUILTIN_PROFILE_PREFIX) :] in caps.BUILTIN_PROFILES:
            return ref
        raise ValidationError({name: "Unknown built-in scan profile."})
    try:
        profile_id = UUID(ref)
    except ValueError:
        raise ValidationError({name: "Not a scan profile id."}) from None
    if not AppSecScanProfile.objects.filter(
        tenant_id=tenant_id, id=profile_id
    ).exists():
        raise ValidationError({name: "Unknown scan profile."})
    return ref


class AppSecViewSet(BaseRLSViewSet):
    """Base: hand-built JSON:API envelopes, read for all, write with manage_scans."""

    queryset = FindingTriage.objects.none()
    serializer_class = FindingTriageSerializer
    pagination_class = None
    filter_backends = []
    parser_classes = [LenientJSONAPIParser, JSONParser]
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]

    def set_required_permissions(self):
        self.required_permissions = (
            [] if self.request.method in SAFE_METHODS else [Permissions.MANAGE_SCANS]
        )

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        # Hand-built envelopes; stop JSON:API re-wrapping (no ``data.data``).
        self.resource_name = False

    def perform_content_negotiation(self, request, force=False):
        # ``?format=csv`` names a file format on the download actions; never
        # let DRF's format override turn it into a renderer lookup (404).
        if self.action in ("export", "download"):
            force = True
        return super().perform_content_negotiation(request, force=force)

    @property
    def tenant_id(self) -> str:
        return str(self.request.tenant_id)

    @property
    def visible(self) -> set[str] | None:
        return visible_provider_ids(self.user_role)

    @property
    def body(self) -> dict[str, Any]:
        data = self.request.data
        if not isinstance(data, dict):
            raise ValidationError({"detail": "The request body must be an object."})
        return data

    def page(self, queryset, serialize, *, meta: dict | None = None) -> Response:
        """Paginate ``queryset`` and return the list envelope."""
        try:
            number, size = queries.page_params(self.request.query_params)
        except queries.QueryError as exc:
            raise ValidationError({"detail": str(exc)}) from exc
        count = queryset.count()
        rows = list(queryset[(number - 1) * size : number * size])
        return Response(
            {
                "data": [serialize(row) for row in rows],
                "meta": {
                    "pagination": {
                        "page": number,
                        "pages": max(1, math.ceil(count / size)),
                        "count": count,
                    },
                    **(meta or {}),
                },
            }
        )


# --- Applications -------------------------------------------------------------


def _application_document(application, stats: dict | None = None) -> dict[str, Any]:
    return {
        "type": _type("applications"),
        "id": str(application.id),
        "attributes": {
            "name": application.name,
            "description": application.description,
            "owner": application.owner,
            "criticality": application.criticality,
            "environment": application.environment,
            "internet_exposed": application.internet_exposed,
            "tags": application.tags,
            "default_profile_ref": application.default_profile_ref,
            "inserted_at": _iso(application.inserted_at),
            "updated_at": _iso(application.updated_at),
            **(stats or {}),
        },
    }


class AppSecApplicationViewSet(AppSecViewSet):
    """Applications: the business grouping of scanned assets."""

    def _queryset(self):
        return AppSecApplication.objects.filter(tenant_id=self.tenant_id)

    def _get(self, pk):
        application = self._queryset().filter(id=_uuid(pk)).first()
        if application is None:
            raise NotFound("Application not found.")
        return application

    def _clean(self, data: dict, *, partial: bool) -> dict[str, Any]:
        cleaned: dict[str, Any] = {}
        name = _text(data, "name", limit=100, required=not partial, minimum=2)
        if name is not None:
            cleaned["name"] = name
        for field, limit in (("description", 2000), ("owner", 200)):
            value = _text(data, field, limit=limit)
            if value is not None:
                cleaned[field] = value
        for field, choices in (
            ("criticality", AppSecApplication.Criticality.choices),
            ("environment", AppSecApplication.Environment.choices),
        ):
            value = _choice(data, field, choices)
            if value is not None:
                cleaned[field] = value
        if "internet_exposed" in data:
            if data["internet_exposed"] not in (True, False, None):
                raise ValidationError(
                    {"internet_exposed": "Must be true, false or null."}
                )
            cleaned["internet_exposed"] = data["internet_exposed"]
        if "tags" in data:
            tags = data["tags"]
            if (
                not isinstance(tags, list)
                or len(tags) > 20
                or not all(
                    isinstance(tag, str) and 0 < len(tag.strip()) <= 40 for tag in tags
                )
            ):
                raise ValidationError(
                    {"tags": "Use up to 20 tags of at most 40 characters."}
                )
            cleaned["tags"] = sorted({tag.strip() for tag in tags})
        if "default_profile_ref" in data:
            cleaned["default_profile_ref"] = _profile_ref(
                self.tenant_id, data["default_profile_ref"], "default_profile_ref"
            )
        return cleaned

    def _assign_targets(self, application, data: dict) -> None:
        """``target_ids`` replaces the set of targets of the application."""
        if "target_ids" not in data:
            return
        ids = data["target_ids"]
        if not isinstance(ids, list):
            raise ValidationError({"target_ids": "Must be a list of target ids."})
        wanted = {_uuid(value, "target") for value in ids}
        targets = queries.visible_targets(self.tenant_id, self.visible)
        if targets.filter(id__in=wanted).count() != len(wanted):
            raise ValidationError({"target_ids": "Unknown target id."})
        targets.filter(application=application).exclude(id__in=wanted).update(
            application=None
        )
        targets.filter(id__in=wanted).update(application=application)

    def _rescore(self, application) -> None:
        from cloudsneeker_api.tasks import appsec_rescore_task

        tenant_id, application_id = self.tenant_id, str(application.id)
        transaction.on_commit(
            lambda: appsec_rescore_task.delay(
                tenant_id=tenant_id, application_id=application_id
            )
        )

    @extend_schema(
        tags=[TAG],
        summary="List applications with their posture",
        responses={200: OpenApiResponse(description="Applications")},
    )
    def list(self, request, *args, **kwargs):
        queryset = self._queryset().order_by("name")
        search = str(request.query_params.get("filter[search]") or "").strip()
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | Q(owner__icontains=search)
            )
        for field in ("criticality", "environment"):
            value = request.query_params.get(f"filter[{field}]")
            if value:
                queryset = queryset.filter(**{field: value})
        try:
            number, size = queries.page_params(request.query_params)
        except queries.QueryError as exc:
            raise ValidationError({"detail": str(exc)}) from exc
        count = queryset.count()
        rows = list(queryset[(number - 1) * size : number * size])
        stats = queries.application_stats(
            self.tenant_id, [str(row.id) for row in rows], self.visible
        )
        return Response(
            {
                "data": [
                    _application_document(row, stats[str(row.id)]) for row in rows
                ],
                "meta": {
                    "pagination": {
                        "page": number,
                        "pages": max(1, math.ceil(count / size)),
                        "count": count,
                    }
                },
            }
        )

    @extend_schema(
        tags=[TAG],
        summary="Get an application and its assets",
        responses={200: OpenApiResponse(description="Application")},
    )
    def retrieve(self, request, pk=None, *args, **kwargs):
        application = self._get(pk)
        stats = queries.application_stats(
            self.tenant_id, [str(application.id)], self.visible
        )[str(application.id)]
        document = _application_document(application, stats)
        targets = queries.visible_targets(self.tenant_id, self.visible).filter(
            application=application
        )
        counts = {
            str(row["target_id"]): row
            for row in queries.findings_queryset(self.tenant_id, self.visible)
            .filter(
                target__in=targets, state__in=queries.ACTIVE_STATES, suppressed=False
            )
            .values("target_id")
            .annotate(
                total=Count("id"),
                critical=Count("id", filter=Q(severity="critical")),
                high=Count("id", filter=Q(severity="high")),
            )
        }
        document["attributes"]["assets"] = [
            {
                "id": str(target.id),
                "name": target.name,
                "target_type": target.mode,
                "provider_uid": target.provider.uid,
                "schedule_enabled": target.schedule_enabled,
                "active_findings": counts.get(str(target.id), {}).get("total", 0),
                "critical": counts.get(str(target.id), {}).get("critical", 0),
                "high": counts.get(str(target.id), {}).get("high", 0),
            }
            for target in targets.select_related("provider").order_by("name")
        ]
        return Response({"data": document})

    @extend_schema(
        tags=[TAG],
        summary="Create an application",
        responses={201: OpenApiResponse(description="Application")},
    )
    def create(self, request, *args, **kwargs):
        cleaned = self._clean(self.body, partial=False)
        if self._queryset().filter(name=cleaned["name"]).exists():
            raise ValidationError(
                {"name": "An application with this name already exists."}
            )
        application = AppSecApplication.objects.create(
            tenant_id=self.tenant_id, **cleaned
        )
        self._assign_targets(application, self.body)
        self._rescore(application)
        return Response(
            {"data": _application_document(application)}, status=status.HTTP_201_CREATED
        )

    @extend_schema(
        tags=[TAG],
        summary="Update an application",
        responses={200: OpenApiResponse(description="Application")},
    )
    def partial_update(self, request, pk=None, *args, **kwargs):
        application = self._get(pk)
        cleaned = self._clean(self.body, partial=True)
        if (
            "name" in cleaned
            and self._queryset()
            .filter(name=cleaned["name"])
            .exclude(id=application.id)
            .exists()
        ):
            raise ValidationError(
                {"name": "An application with this name already exists."}
            )
        for field, value in cleaned.items():
            setattr(application, field, value)
        application.save()
        self._assign_targets(application, self.body)
        self._rescore(application)
        return Response({"data": _application_document(application)})

    @extend_schema(
        tags=[TAG],
        summary="Delete an application (its assets stay)",
        responses={204: OpenApiResponse(description="Deleted")},
    )
    def destroy(self, request, pk=None, *args, **kwargs):
        application = self._get(pk)
        targets = list(application.targets.values_list("id", flat=True))
        application.delete()
        if targets:
            from cloudsneeker_api.tasks import appsec_rescore_task

            tenant_id = self.tenant_id
            ids = [str(pk) for pk in targets]
            transaction.on_commit(
                lambda: appsec_rescore_task.delay(tenant_id=tenant_id, target_ids=ids)
            )
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Scan profiles ------------------------------------------------------------


def _profile_document(profile) -> dict[str, Any]:
    return {
        "type": _type("scan-profiles"),
        "id": str(profile.id),
        "attributes": {
            "ref": str(profile.id),
            "builtin": False,
            "name": profile.name,
            "description": profile.description,
            "target_types": profile.target_types,
            "options": profile.options,
            "enabled": profile.enabled,
            "inserted_at": _iso(profile.inserted_at),
            "updated_at": _iso(profile.updated_at),
        },
    }


def _builtin_profile_documents() -> list[dict[str, Any]]:
    return [
        {
            "type": _type("scan-profiles"),
            "id": f"{caps.BUILTIN_PROFILE_PREFIX}{key}",
            "attributes": {
                "ref": f"{caps.BUILTIN_PROFILE_PREFIX}{key}",
                "builtin": True,
                "enabled": True,
                "inserted_at": None,
                "updated_at": None,
                **profile,
            },
        }
        for key, profile in caps.BUILTIN_PROFILES.items()
    ]


class AppSecScanProfileViewSet(AppSecViewSet):
    """Reusable scan options. Built-in profiles are read only."""

    def _queryset(self):
        return AppSecScanProfile.objects.filter(tenant_id=self.tenant_id)

    def _get(self, pk):
        profile = self._queryset().filter(id=_uuid(pk)).first()
        if profile is None:
            raise NotFound("Scan profile not found.")
        return profile

    def _clean(self, data: dict, *, instance=None) -> dict[str, Any]:
        cleaned: dict[str, Any] = {}
        name = _text(data, "name", limit=100, required=instance is None, minimum=3)
        if name is not None:
            cleaned["name"] = name
        description = _text(data, "description", limit=2000)
        if description is not None:
            cleaned["description"] = description
        if "enabled" in data:
            if not isinstance(data["enabled"], bool):
                raise ValidationError({"enabled": "Must be true or false."})
            cleaned["enabled"] = data["enabled"]
        target_types = data.get(
            "target_types", instance.target_types if instance else []
        )
        options = data.get("options", instance.options if instance else None)
        if instance is None and "options" not in data:
            raise ValidationError({"options": "This field is required."})
        if not isinstance(target_types, list):
            raise ValidationError({"target_types": "Must be a list of target types."})
        try:
            validate_profile_options(options, target_types)
        except OptionError as exc:
            raise ValidationError({"options": str(exc)}) from exc
        cleaned["target_types"] = target_types
        cleaned["options"] = options
        return cleaned

    @extend_schema(
        tags=[TAG],
        summary="List scan profiles (built-in first)",
        responses={200: OpenApiResponse(description="Scan profiles")},
    )
    def list(self, request, *args, **kwargs):
        documents = _builtin_profile_documents() + [
            _profile_document(row) for row in self._queryset().order_by("name")
        ]
        return Response({"data": documents, "meta": {"count": len(documents)}})

    @extend_schema(
        tags=[TAG],
        summary="Get a scan profile",
        responses={200: OpenApiResponse(description="Scan profile")},
    )
    def retrieve(self, request, pk=None, *args, **kwargs):
        if str(pk).startswith(caps.BUILTIN_PROFILE_PREFIX):
            for document in _builtin_profile_documents():
                if document["id"] == pk:
                    return Response({"data": document})
            raise NotFound("Scan profile not found.")
        return Response({"data": _profile_document(self._get(pk))})

    @extend_schema(
        tags=[TAG],
        summary="Create a scan profile",
        responses={201: OpenApiResponse(description="Scan profile")},
    )
    def create(self, request, *args, **kwargs):
        cleaned = self._clean(self.body)
        if self._queryset().filter(name=cleaned["name"]).exists():
            raise ValidationError(
                {"name": "A scan profile with this name already exists."}
            )
        profile = AppSecScanProfile.objects.create(
            tenant_id=self.tenant_id,
            created_by_id=getattr(request.user, "id", None),
            **cleaned,
        )
        return Response(
            {"data": _profile_document(profile)}, status=status.HTTP_201_CREATED
        )

    @extend_schema(
        tags=[TAG],
        summary="Update a scan profile",
        responses={200: OpenApiResponse(description="Scan profile")},
    )
    def partial_update(self, request, pk=None, *args, **kwargs):
        profile = self._get(pk)
        cleaned = self._clean(self.body, instance=profile)
        if (
            "name" in cleaned
            and self._queryset()
            .filter(name=cleaned["name"])
            .exclude(id=profile.id)
            .exists()
        ):
            raise ValidationError(
                {"name": "A scan profile with this name already exists."}
            )
        for field, value in cleaned.items():
            setattr(profile, field, value)
        profile.save()
        return Response({"data": _profile_document(profile)})

    @extend_schema(
        tags=[TAG],
        summary="Delete a scan profile",
        responses={204: OpenApiResponse(description="Deleted")},
    )
    def destroy(self, request, pk=None, *args, **kwargs):
        profile = self._get(pk)
        ref = str(profile.id)
        in_use = TrivyTarget.objects.filter(
            tenant_id=self.tenant_id, config__profile=ref
        ).count()
        in_use += AppSecApplication.objects.filter(
            tenant_id=self.tenant_id, default_profile_ref=ref
        ).count()
        if in_use:
            raise ValidationError(
                {
                    "detail": f"The profile is used by {in_use} target(s) or application(s). "
                    "Reassign them first, or disable the profile."
                }
            )
        profile.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Policies -----------------------------------------------------------------


def _policy_document(policy, *, content: bool = False, versions=None) -> dict[str, Any]:
    attributes = {
        "kind": policy.kind,
        "name": policy.name,
        "description": policy.description,
        "enabled": policy.enabled,
        "version": policy.version,
        "validation": policy.validation,
        "inserted_at": _iso(policy.inserted_at),
        "updated_at": _iso(policy.updated_at),
    }
    if content:
        attributes["content"] = policy.content
    if versions is not None:
        attributes["versions"] = versions
    return {"type": _type("policies"), "id": str(policy.id), "attributes": attributes}


class AppSecPolicyViewSet(AppSecViewSet):
    """Custom checks, secret rules, license policy, ignore rules and VEX."""

    def _queryset(self):
        return AppSecPolicy.objects.filter(tenant_id=self.tenant_id)

    def _get(self, pk):
        policy = self._queryset().filter(id=_uuid(pk)).first()
        if policy is None:
            raise NotFound("Policy not found.")
        return policy

    @staticmethod
    def _validate(kind: str, content: Any) -> dict[str, Any]:
        result = policy_rules.validate_policy(kind, content)
        if not result.valid:
            raise ValidationError({"content": result.errors})
        return result.to_dict()

    @extend_schema(
        tags=[TAG],
        summary="List policies",
        responses={200: OpenApiResponse(description="Policies")},
    )
    def list(self, request, *args, **kwargs):
        queryset = self._queryset().order_by("kind", "name")
        kind = request.query_params.get("filter[kind]")
        if kind:
            queryset = queryset.filter(kind=kind)
        return self.page(queryset, _policy_document)

    @extend_schema(
        tags=[TAG],
        summary="Get a policy with its content and versions",
        responses={200: OpenApiResponse(description="Policy")},
    )
    def retrieve(self, request, pk=None, *args, **kwargs):
        policy = self._get(pk)
        versions = [
            {
                "version": row.version,
                "inserted_at": _iso(row.inserted_at),
                "content": row.content,
            }
            for row in policy.versions.order_by("-version")[:20]
        ]
        return Response(
            {"data": _policy_document(policy, content=True, versions=versions)}
        )

    @extend_schema(
        tags=[TAG],
        summary="Create a policy",
        responses={201: OpenApiResponse(description="Policy")},
    )
    def create(self, request, *args, **kwargs):
        data = self.body
        kind = _choice({"kind": data.get("kind")}, "kind", AppSecPolicy.Kind.choices)
        name = _text(data, "name", limit=100, required=True, minimum=3)
        validation = self._validate(kind, data.get("content"))
        if self._queryset().filter(kind=kind, name=name).exists():
            raise ValidationError(
                {"name": "A policy of this kind already has this name."}
            )
        policy = AppSecPolicy.objects.create(
            tenant_id=self.tenant_id,
            kind=kind,
            name=name,
            description=_text(data, "description", limit=2000) or "",
            content=data["content"],
            enabled=bool(data.get("enabled", True)),
            validation=validation,
            updated_by_id=getattr(request.user, "id", None),
        )
        return Response(
            {"data": _policy_document(policy, content=True)},
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(
        tags=[TAG],
        summary="Update a policy; new content is a new version",
        responses={200: OpenApiResponse(description="Policy")},
    )
    def partial_update(self, request, pk=None, *args, **kwargs):
        policy = self._get(pk)
        data = self.body
        if "kind" in data and data["kind"] != policy.kind:
            raise ValidationError({"kind": "The kind of a policy cannot change."})
        name = _text(data, "name", limit=100, minimum=3)
        if name is not None and name != policy.name:
            if self._queryset().filter(kind=policy.kind, name=name).exists():
                raise ValidationError(
                    {"name": "A policy of this kind already has this name."}
                )
            policy.name = name
        description = _text(data, "description", limit=2000)
        if description is not None:
            policy.description = description
        if "enabled" in data:
            if not isinstance(data["enabled"], bool):
                raise ValidationError({"enabled": "Must be true or false."})
            policy.enabled = data["enabled"]
        if "content" in data and data["content"] != policy.content:
            policy.validation = self._validate(policy.kind, data["content"])
            AppSecPolicyVersion.objects.create(
                tenant_id=self.tenant_id,
                policy=policy,
                version=policy.version,
                content=policy.content,
                created_by_id=policy.updated_by_id,
            )
            policy.content = data["content"]
            policy.version += 1
        policy.updated_by_id = getattr(request.user, "id", None)
        policy.save()
        return Response({"data": _policy_document(policy, content=True)})

    @extend_schema(
        tags=[TAG],
        summary="Delete a policy",
        responses={204: OpenApiResponse(description="Deleted")},
    )
    def destroy(self, request, pk=None, *args, **kwargs):
        self._get(pk).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        tags=[TAG],
        summary="Validate policy content without saving it",
        responses={200: OpenApiResponse(description="Validation result")},
    )
    @action(detail=False, methods=["post"], url_path="validate", url_name="validate")
    def validate(self, request):
        data = self.body
        result = policy_rules.validate_policy(
            str(data.get("kind") or ""), data.get("content")
        )
        return Response(
            {
                "data": {
                    "type": _type("policy-validations"),
                    "id": "validation",
                    "attributes": result.to_dict(),
                }
            }
        )


# --- Findings -----------------------------------------------------------------

EXPORT_COLUMNS = (
    "uid",
    "category",
    "severity",
    "priority",
    "priority_score",
    "state",
    "triage_status",
    "rule_id",
    "title",
    "pkg_name",
    "pkg_version",
    "fixed_version",
    "ecosystem",
    "file_path",
    "start_line",
    "resource",
    "cvss_score",
    "fix_available",
    "application_name",
    "target_name",
    "target_type",
    "first_seen_at",
    "last_seen_at",
    "due_at",
)


def _finding_document(finding, *, detail: bool = False) -> dict[str, Any]:
    return {
        "type": _type("findings"),
        "id": str(finding.id),
        "attributes": queries.finding_row(finding, detail=detail),
    }


class AppSecFindingViewSet(AppSecViewSet):
    """Persistent findings across scans, with detection state and priority."""

    http_method_names = ["get", "head", "options"]

    def _filtered(self):
        queryset = queries.findings_queryset(self.tenant_id, self.visible)
        try:
            queryset = queries.filter_findings(
                queryset, self.request.query_params, now=timezone.now()
            )
            return queries.sort_findings(
                queryset, self.request.query_params.get("sort")
            )
        except queries.QueryError as exc:
            raise ValidationError({"detail": str(exc)}) from exc

    @extend_schema(
        tags=[TAG],
        summary="List findings",
        responses={200: OpenApiResponse(description="Findings")},
    )
    def list(self, request, *args, **kwargs):
        queryset = self._filtered().select_related("target", "target__application")
        return self.page(queryset, _finding_document)

    @extend_schema(
        tags=[TAG],
        summary="Get a finding with history and related findings",
        responses={200: OpenApiResponse(description="Finding")},
    )
    def retrieve(self, request, pk=None, *args, **kwargs):
        base = queries.findings_queryset(self.tenant_id, self.visible).select_related(
            "target", "target__application"
        )
        finding = base.filter(id=_uuid(pk)).first()
        if finding is None:
            raise NotFound("Finding not found.")
        document = _finding_document(finding, detail=True)
        events = AppSecFindingEvent.objects.filter(
            tenant_id=self.tenant_id, finding=finding
        ).order_by("-inserted_at")[:50]
        document["attributes"]["events"] = [
            {
                "kind": event.kind,
                "at": _iso(event.inserted_at),
                "run_id": str(event.run_id) if event.run_id else None,
                "detail": event.detail,
            }
            for event in events
        ]
        related = base.exclude(id=finding.id).filter(suppressed=False)
        if (
            finding.category == AppSecFinding.Category.VULNERABILITY
            and finding.pkg_name
        ):
            same_rule = related.filter(rule_id=finding.rule_id)
            same_package = related.filter(
                target=finding.target,
                pkg_name=finding.pkg_name,
                category=finding.category,
            ).exclude(rule_id=finding.rule_id)
        else:
            same_rule = related.filter(
                rule_id=finding.rule_id, category=finding.category
            )
            same_package = related.none()
        document["attributes"]["related"] = {
            "same_rule_total": same_rule.count(),
            "same_rule": [
                _finding_document(row)
                for row in same_rule.order_by("-priority_score")[:10]
            ],
            "same_package_total": same_package.count(),
            "same_package": [
                _finding_document(row)
                for row in same_package.order_by("-priority_score")[:10]
            ],
        }
        runs = TrivyRun.objects.filter(
            tenant_id=self.tenant_id, target=finding.target
        ).order_by("-inserted_at")[:10]
        document["attributes"]["recent_scans"] = [
            {
                "id": str(run.id),
                "status": run.status,
                "at": _iso(run.inserted_at),
                "engine_version": run.engine_version,
            }
            for run in runs
        ]
        return Response({"data": document})

    @extend_schema(
        tags=[TAG],
        summary="Figures for the current filters",
        responses={200: OpenApiResponse(description="Summary")},
    )
    @action(detail=False, methods=["get"], url_path="summary", url_name="summary")
    def summary(self, request):
        queryset = queries.findings_queryset(self.tenant_id, self.visible)
        params = request.query_params.copy()
        # The summary reports every state and suppression itself.
        params["filter[state__in]"] = "new,open,reopened,fixed"
        params["filter[suppressed]"] = "any"
        try:
            scoped = queries.filter_findings(queryset, params, now=timezone.now())
        except queries.QueryError as exc:
            raise ValidationError({"detail": str(exc)}) from exc
        summary = queries.findings_summary(scoped, now=timezone.now())
        return Response(
            {
                "data": {
                    "type": _type("finding-summaries"),
                    "id": "summary",
                    "attributes": summary,
                }
            }
        )

    @extend_schema(
        tags=[TAG],
        summary="Export the filtered findings as CSV or JSON",
        responses={200: OpenApiResponse(description="File")},
    )
    @action(detail=False, methods=["get"], url_path="export", url_name="export")
    def export(self, request):
        fmt = str(request.query_params.get("format") or "csv").lower()
        if fmt not in ("csv", "json"):
            raise ValidationError({"format": "Use csv or json."})
        rows = [
            queries.finding_row(finding)
            for finding in self._filtered().select_related(
                "target", "target__application"
            )[: queries.EXPORT_MAX_ROWS]
        ]
        stamp = timezone.now().strftime("%Y%m%d-%H%M")
        if fmt == "json":
            body = json.dumps(
                {"generated_at": timezone.now().isoformat(), "findings": rows}
            )
            content_type = "application/json"
        else:
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(EXPORT_COLUMNS)
            for row in rows:
                writer.writerow(
                    [_csv_cell(row.get(column)) for column in EXPORT_COLUMNS]
                )
            body = buffer.getvalue()
            content_type = "text/csv"
        response = HttpResponse(body, content_type=content_type)
        response["Content-Disposition"] = (
            f'attachment; filename="cloudsneeker-appsec-findings-{stamp}.{fmt}"'
        )
        return response


def _csv_cell(value: Any) -> str:
    """Text for a CSV cell; a leading formula character is neutralized."""
    text = "" if value is None else str(value)
    return f"'{text}" if text[:1] in ("=", "+", "-", "@") else text


# --- SBOMs and components -----------------------------------------------------


def _sbom_document(record) -> dict[str, Any]:
    return {
        "type": _type("sboms"),
        "id": str(record.id),
        "attributes": {
            "target_id": str(record.target_id),
            "target_name": record.target.name,
            "target_type": record.target.mode,
            "application_id": (
                str(record.target.application_id)
                if record.target.application_id
                else None
            ),
            "application_name": (
                record.target.application.name if record.target.application_id else None
            ),
            "run_id": str(record.run_id) if record.run_id else None,
            "source": record.source,
            "document_format": record.document_format,
            "version": record.version,
            "artifact_name": record.artifact_name,
            "artifact_type": record.artifact_type,
            "component_count": record.component_count,
            "vulnerable_component_count": record.vulnerable_component_count,
            "vulnerability_count": record.vulnerability_count,
            "summary": record.summary,
            "inserted_at": _iso(record.inserted_at),
        },
    }


def _component_document(component) -> dict[str, Any]:
    return {
        "type": _type("components"),
        "id": str(component.id),
        "attributes": {
            "sbom_id": str(component.sbom_id),
            "target_id": str(component.target_id),
            "target_name": component.target.name,
            "name": component.name,
            "version": component.version,
            "ecosystem": component.ecosystem,
            "package_class": component.package_class,
            "purl": component.purl,
            "licenses": component.licenses,
            "relationship": component.relationship,
            "dev": component.dev,
            "location": component.location,
            "depends_on": component.depends_on,
            "vulnerability_count": component.vulnerability_count,
            "max_severity": component.max_severity,
            "fixed_version": component.fixed_version,
        },
    }


def _filter_components(queryset, params):
    search = str(params.get("filter[search]") or "").strip()
    if search:
        queryset = queryset.filter(
            Q(name__icontains=search) | Q(purl__icontains=search)
        )
    for name in ("ecosystem", "relationship", "package_class", "name"):
        value = params.get(f"filter[{name}]")
        if value:
            queryset = queryset.filter(**{name: value})
    license_name = params.get("filter[license]")
    if license_name:
        queryset = queryset.filter(licenses__contains=[license_name])
    vulnerable = params.get("filter[vulnerable]")
    if vulnerable in ("true", "1"):
        queryset = queryset.filter(vulnerability_count__gt=0)
    elif vulnerable in ("false", "0"):
        queryset = queryset.filter(vulnerability_count=0)
    if params.get("filter[unlicensed]") in ("true", "1"):
        queryset = queryset.filter(licenses=[])
    sort = str(params.get("sort") or "-vulnerability_count")
    allowed = {"name", "version", "ecosystem", "vulnerability_count", "relationship"}
    if sort.lstrip("-") not in allowed:
        raise ValidationError({"sort": f"Use one of: {', '.join(sorted(allowed))}."})
    return queryset.order_by(sort, "name", "id")


def _component_dicts(sbom_id) -> list[dict[str, Any]]:
    return list(
        AppSecComponent.objects.filter(sbom_id=sbom_id).values(
            "ref",
            "name",
            "version",
            "ecosystem",
            "purl",
            "licenses",
            "relationship",
            "location",
            "depends_on",
        )
    )


class AppSecSbomViewSet(AppSecViewSet):
    """Software inventories: one per completed scan that listed packages."""

    http_method_names = ["get", "head", "options"]

    def _queryset(self):
        targets = queries.visible_targets(self.tenant_id, self.visible)
        return AppSecSbom.objects.filter(
            tenant_id=self.tenant_id, target__in=targets
        ).select_related("target", "target__application")

    def _get(self, pk):
        record = self._queryset().filter(id=_uuid(pk)).first()
        if record is None:
            raise NotFound("SBOM not found.")
        return record

    @extend_schema(
        tags=[TAG],
        summary="List SBOMs (newest first)",
        responses={200: OpenApiResponse(description="SBOMs")},
    )
    def list(self, request, *args, **kwargs):
        queryset = self._queryset().order_by("-inserted_at")
        params = request.query_params
        if params.get("filter[target]"):
            queryset = queryset.filter(target_id=params["filter[target]"])
        if params.get("filter[application]"):
            queryset = queryset.filter(
                target__application_id=params["filter[application]"]
            )
        if params.get("filter[latest]") in ("true", "1"):
            queryset = queryset.filter(
                id__in=queries.latest_sbom_ids(
                    self.tenant_id,
                    queries.visible_targets(self.tenant_id, self.visible),
                )
            )
        return self.page(queryset, _sbom_document)

    @extend_schema(
        tags=[TAG],
        summary="Get an SBOM and the versions of its target",
        responses={200: OpenApiResponse(description="SBOM")},
    )
    def retrieve(self, request, pk=None, *args, **kwargs):
        record = self._get(pk)
        document = _sbom_document(record)
        document["attributes"]["versions"] = [
            {
                "id": str(row.id),
                "version": row.version,
                "inserted_at": _iso(row.inserted_at),
                "component_count": row.component_count,
                "vulnerability_count": row.vulnerability_count,
            }
            for row in self._queryset()
            .filter(target=record.target)
            .order_by("-version")[:50]
        ]
        run = record.run
        formats = ["cyclonedx"]
        if run is not None and run.artifact_path and record.target.mode != "k8s":
            formats.append("spdx-json")
        document["attributes"]["download_formats"] = formats
        return Response({"data": document})

    @extend_schema(
        tags=[TAG],
        summary="Components of an SBOM",
        responses={200: OpenApiResponse(description="Components")},
    )
    @action(detail=True, methods=["get"], url_path="components", url_name="components")
    def components(self, request, pk=None):
        record = self._get(pk)
        queryset = _filter_components(
            AppSecComponent.objects.filter(
                tenant_id=self.tenant_id, sbom=record
            ).select_related("target"),
            request.query_params,
        )
        return self.page(queryset, _component_document)

    @extend_schema(
        tags=[TAG],
        summary="Compare with an earlier SBOM of the same target",
        responses={200: OpenApiResponse(description="Added, removed, changed")},
    )
    @action(detail=True, methods=["get"], url_path="compare", url_name="compare")
    def compare(self, request, pk=None):
        head = self._get(pk)
        base = self._get(request.query_params.get("base"))
        if base.target_id != head.target_id:
            raise ValidationError(
                {"base": "Both SBOMs must belong to the same target."}
            )
        diff = sbom.diff_components(
            _component_dicts(base.id), _component_dicts(head.id)
        )
        limit = 500
        return Response(
            {
                "data": {
                    "type": _type("sbom-comparisons"),
                    "id": f"{base.id}..{head.id}",
                    "attributes": {
                        "base": {
                            "id": str(base.id),
                            "version": base.version,
                            "inserted_at": _iso(base.inserted_at),
                        },
                        "head": {
                            "id": str(head.id),
                            "version": head.version,
                            "inserted_at": _iso(head.inserted_at),
                        },
                        "counts": {
                            "added": len(diff["added"]),
                            "removed": len(diff["removed"]),
                            "changed": len(diff["changed"]),
                            "unchanged": diff["unchanged"],
                        },
                        "added": diff["added"][:limit],
                        "removed": diff["removed"][:limit],
                        "changed": diff["changed"][:limit],
                        "truncated": any(
                            len(diff[key]) > limit
                            for key in ("added", "removed", "changed")
                        ),
                    },
                }
            }
        )

    @extend_schema(
        tags=[TAG],
        summary="Download an SBOM as CycloneDX or SPDX",
        responses={200: OpenApiResponse(description="File")},
    )
    @action(detail=True, methods=["get"], url_path="download", url_name="download")
    def download(self, request, pk=None):
        from cloudsneeker_api.appsec import engine
        from cloudsneeker_api.brand import brand

        record = self._get(pk)
        fmt = str(request.query_params.get("format") or "cyclonedx").lower()
        if fmt not in ("cyclonedx", "spdx-json"):
            raise ValidationError({"format": "Use cyclonedx or spdx-json."})
        body: bytes | None = None
        run = record.run
        if run is not None and run.artifact_path and record.target.mode != "k8s":
            report = engine.load_report(run)
            if report is not None:
                try:
                    body = engine.convert_report(report, fmt)
                except engine.EngineError:
                    body = None
        if body is None:
            if fmt != "cyclonedx":
                raise ValidationError(
                    {
                        "format": "The scan report is no longer stored; only CycloneDX "
                        "can be built from the saved inventory."
                    }
                )
            document = sbom.build_cyclonedx(
                _component_dicts(record.id),
                name=record.artifact_name or record.target.name,
                created_at=record.inserted_at,
                tool_name=brand.name,
                tool_version=run.engine_version if run else "",
            )
            body = json.dumps(document, indent=2).encode("utf-8")
        _, content_type, extension = engine.CONVERT_FORMATS[fmt]
        response = HttpResponse(body, content_type=content_type)
        response["Content-Disposition"] = (
            f'attachment; filename="cloudsneeker-sbom-{record.target_id}-v{record.version}.{extension}"'
        )
        return response


class AppSecComponentViewSet(AppSecViewSet):
    """Components of the newest SBOM of every target (the current inventory)."""

    http_method_names = ["get", "head", "options"]

    def _queryset(self):
        targets = queries.visible_targets(self.tenant_id, self.visible)
        params = self.request.query_params
        if params.get("filter[target]"):
            targets = targets.filter(id=params["filter[target]"])
        if params.get("filter[application]"):
            targets = targets.filter(application_id=params["filter[application]"])
        return AppSecComponent.objects.filter(
            tenant_id=self.tenant_id,
            sbom_id__in=queries.latest_sbom_ids(self.tenant_id, targets),
        )

    @extend_schema(
        tags=[TAG],
        summary="List components of the current inventory",
        responses={200: OpenApiResponse(description="Components")},
    )
    def list(self, request, *args, **kwargs):
        queryset = _filter_components(
            self._queryset().select_related("target"), request.query_params
        )
        return self.page(queryset, _component_document)

    @extend_schema(
        tags=[TAG],
        summary="Ecosystems and licenses of the current inventory",
        responses={200: OpenApiResponse(description="Summary")},
    )
    @action(detail=False, methods=["get"], url_path="summary", url_name="summary")
    def summary(self, request):
        queryset = self._queryset()
        rows = queryset.values(
            "ecosystem", "relationship", "licenses", "vulnerability_count"
        )
        summary = sbom.summarize(rows.iterator(chunk_size=2000))
        summary["vulnerable"] = queryset.filter(vulnerability_count__gt=0).count()
        summary["distinct_packages"] = (
            queryset.values("ecosystem", "name").distinct().count()
        )
        return Response(
            {
                "data": {
                    "type": _type("component-summaries"),
                    "id": "summary",
                    "attributes": summary,
                }
            }
        )


# --- Overview, engine, settings -----------------------------------------------


def _settings_attributes(row) -> dict[str, Any]:
    return {
        "risk": merge_risk_config(row.risk if row else None),
        "risk_overrides": (row.risk if row else None) or {},
        "risk_defaults": DEFAULT_RISK_CONFIG,
        "sla_days": merge_sla_days(row.sla_days if row else None),
        "sla_defaults": DEFAULT_SLA_DAYS,
        "retention": {
            "sbom_versions": 10,
            "raw_artifact_days": 90,
            "fixed_findings_days": 365,
            **((row.retention if row else None) or {}),
        },
        "default_profiles": (row.default_profiles if row else None) or {},
        "updated_at": _iso(row.updated_at) if row else None,
    }


RETENTION_LIMITS = {
    "sbom_versions": (1, 100),
    "raw_artifact_days": (1, 3650),
    "fixed_findings_days": (30, 3650),
}


class AppSecPlatformViewSet(AppSecViewSet):
    """Overview figures, the capability matrix, engine status and settings."""

    http_method_names = ["get", "patch", "head", "options"]

    def set_required_permissions(self):
        super().set_required_permissions()
        # Listing branches reads the source with its stored credentials and
        # only serves target editing, which needs manage_scans.
        if self.action == "repository_branches":
            self.required_permissions = [Permissions.MANAGE_SCANS]

    @extend_schema(
        tags=[TAG],
        summary="Branches of a code repository source",
        parameters=[
            OpenApiParameter(
                "provider_id",
                str,
                required=True,
                description="Code repository (IaC) source to list branches of.",
            )
        ],
        responses={
            200: OpenApiResponse(description="Branches, default branch first"),
            502: OpenApiResponse(description="The repository could not be read"),
        },
    )
    @action(
        detail=False,
        methods=["get"],
        url_path="repository-branches",
        url_name="repository-branches",
    )
    def repository_branches(self, request):
        raw_id = str(request.query_params.get("provider_id") or "").strip()
        try:
            provider_id = UUID(raw_id)
        except ValueError:
            raise ValidationError({"provider_id": "Must be a source id."}) from None
        visible = self.visible
        if visible is not None and str(provider_id) not in visible:
            raise NotFound("Source not found.")
        provider = (
            Provider.objects.filter(tenant_id=self.tenant_id, id=provider_id)
            .select_related("secret")
            .first()
        )
        if provider is None:
            raise NotFound("Source not found.")
        if provider.provider != Provider.ProviderChoices.IAC.value:
            raise ValidationError(
                {"provider_id": "Branches are listed only for code repository sources."}
            )
        try:
            listing = list_repository_branches(provider.uid, provider)
        except RepositoryBranchError as exc:
            # Error responses are wrapped in ``{"errors": ...}`` by the
            # JSON:API renderer, so the body is the error list itself.
            return Response(
                [
                    {
                        "status": "502",
                        "code": "repository_unreachable",
                        "detail": scrub_engine_text(str(exc)),
                    }
                ],
                status=status.HTTP_502_BAD_GATEWAY,
            )
        return Response(
            {
                "data": [
                    {
                        "type": _type("branches"),
                        "id": name,
                        "attributes": {
                            "name": name,
                            "default": name == listing.default_branch,
                        },
                    }
                    for name in listing.branches
                ],
                "meta": {
                    "provider_id": str(provider.id),
                    "default_branch": listing.default_branch,
                    "count": len(listing.branches),
                    "truncated": listing.truncated,
                },
            }
        )

    @extend_schema(exclude=True)
    def list(self, request, *args, **kwargs):
        raise NotFound()

    @extend_schema(exclude=True)
    def retrieve(self, request, *args, **kwargs):
        raise NotFound()

    @extend_schema(
        tags=[TAG],
        summary="Application Security overview figures",
        responses={200: OpenApiResponse(description="Overview")},
    )
    @action(detail=False, methods=["get"], url_path="overview", url_name="overview")
    def overview(self, request):
        try:
            days = max(7, min(180, int(request.query_params.get("days") or 30)))
        except (TypeError, ValueError):
            raise ValidationError({"days": "Must be a whole number."}) from None
        data = queries.overview(
            self.tenant_id, self.visible, now=timezone.now(), days=days
        )
        return Response(
            {"data": {"type": _type("overviews"), "id": "overview", "attributes": data}}
        )

    @extend_schema(
        tags=[TAG],
        summary="Target, scanner and option matrix",
        responses={200: OpenApiResponse(description="Capabilities")},
    )
    @action(
        detail=False, methods=["get"], url_path="capabilities", url_name="capabilities"
    )
    def capabilities(self, request):
        return Response(
            {
                "data": {
                    "type": _type("capabilities"),
                    "id": caps.ENGINE_VERSION,
                    "attributes": caps.capability_document(),
                }
            }
        )

    @extend_schema(
        tags=[TAG],
        summary="Scan engine version, database and limits",
        responses={200: OpenApiResponse(description="Engine status")},
    )
    @action(detail=False, methods=["get"], url_path="engine", url_name="engine")
    def engine(self, request):
        from cloudsneeker_api.appsec import engine
        from cloudsneeker_api.services import content_versions

        runs = TrivyRun.objects.filter(tenant_id=self.tenant_id)
        since = timezone.now() - timedelta(days=7)
        recent = runs.filter(inserted_at__gte=since)
        attributes = {
            "engine": engine.engine_status(),
            "vulnerability_database": content_versions.vulnerability_database(),
            "limits": engine.engine_limits(),
            "direct_target_types": sorted(engine.direct_modes()),
            "queue": {
                "pending": runs.filter(status="pending").count(),
                "running": runs.filter(status="running").count(),
            },
            "last_7_days": {
                "total": recent.count(),
                "by_status": {
                    row["status"]: row["count"]
                    for row in recent.values("status")
                    .annotate(count=Count("id"))
                    .order_by()
                },
                "by_failure": {
                    row["error_class"]: row["count"]
                    for row in recent.filter(status="failed")
                    .values("error_class")
                    .annotate(count=Count("id"))
                    .order_by()
                },
            },
        }
        return Response(
            {
                "data": {
                    "type": _type("engine-status"),
                    "id": "engine",
                    "attributes": attributes,
                }
            }
        )

    @extend_schema(
        tags=[TAG],
        summary="Tenant risk, deadline and retention settings",
        responses={200: OpenApiResponse(description="Settings")},
    )
    @action(
        detail=False, methods=["get", "patch"], url_path="settings", url_name="settings"
    )
    def tenant_settings(self, request):
        row = AppSecSettings.objects.filter(tenant_id=self.tenant_id).first()
        if request.method == "PATCH":
            data = self.body
            row = row or AppSecSettings(tenant_id=self.tenant_id)
            rescore = False
            try:
                if "risk" in data:
                    merge_risk_config(data["risk"])
                    row.risk = data["risk"] or {}
                    rescore = True
                if "sla_days" in data:
                    merge_sla_days(data["sla_days"])
                    row.sla_days = data["sla_days"] or {}
                    rescore = True
            except RiskConfigError as exc:
                raise ValidationError({"detail": str(exc)}) from exc
            if "retention" in data:
                retention = data["retention"]
                if not isinstance(retention, dict) or set(retention) - set(
                    RETENTION_LIMITS
                ):
                    raise ValidationError(
                        {"retention": f"Use: {', '.join(RETENTION_LIMITS)}."}
                    )
                for key, value in retention.items():
                    low, high = RETENTION_LIMITS[key]
                    if (
                        isinstance(value, bool)
                        or not isinstance(value, int)
                        or not low <= value <= high
                    ):
                        raise ValidationError(
                            {"retention": f"{key} must be between {low} and {high}."}
                        )
                row.retention = retention
            if "default_profiles" in data:
                defaults = data["default_profiles"]
                if not isinstance(defaults, dict) or set(defaults) - set(caps.TARGETS):
                    raise ValidationError(
                        {"default_profiles": "Keys must be target types."}
                    )
                row.default_profiles = {
                    key: _profile_ref(self.tenant_id, value, "default_profiles")
                    for key, value in defaults.items()
                    if value
                }
            row.updated_by_id = getattr(request.user, "id", None)
            row.save()
            if rescore:
                from cloudsneeker_api.tasks import appsec_rescore_task

                tenant_id = self.tenant_id
                transaction.on_commit(
                    lambda: appsec_rescore_task.delay(tenant_id=tenant_id)
                )
        return Response(
            {
                "data": {
                    "type": _type("settings"),
                    "id": "settings",
                    "attributes": _settings_attributes(row),
                }
            }
        )
