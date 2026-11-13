"""JSON:API serializers for Trivy Hub targets and runs."""

from api.models import Provider
from api.v1.serializers import BaseWriteSerializer, RLSSerializer
from cloudsneeker_api.models import (
    JSON_API_TYPE_PREFIX,
    AppSecApplication,
    TrivyRun,
    TrivyTarget,
)
from cloudsneeker_api.services.brand_text import scrub_engine_text
from cloudsneeker_api.services.custodian_schedule import (
    CustodianScheduleError,
    validate_timezone,
)
from cloudsneeker_api.services.repo_branches import name_for_branch, run_branch
from cloudsneeker_api.services.trivy import (
    REPOSITORY_URL_MODES,
    TrivyHubError,
    assert_provider_matches_mode,
    effective_run_status,
    is_valid_trivy_mode,
    validate_target_config,
)
from cloudsneeker_api.services.trivy_schedule import (
    TrivyScheduleError,
    sync_target_schedule,
)
from rest_framework import serializers
from rest_framework.exceptions import ValidationError


class TrivyTargetSerializer(RLSSerializer):
    """Read serializer for Trivy Hub targets."""

    provider_id = serializers.UUIDField(source="provider.id", read_only=True)
    provider_uid = serializers.CharField(source="provider.uid", read_only=True)
    provider_alias = serializers.CharField(
        source="provider.alias", read_only=True, allow_null=True
    )
    provider_type = serializers.CharField(source="provider.provider", read_only=True)

    class Meta:
        model = TrivyTarget
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "description",
            "mode",
            "config",
            "provider_id",
            "provider_uid",
            "provider_alias",
            "provider_type",
            "schedule_enabled",
            "schedule_cron",
            "schedule_timezone",
            "next_run_at",
            "application_id",
            "application_name",
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}trivy-targets"

    application_id = serializers.UUIDField(read_only=True, allow_null=True)
    application_name = serializers.CharField(
        source="application.name", read_only=True, allow_null=True, default=None
    )


class TrivyTargetWriteSerializer(RLSSerializer, BaseWriteSerializer):
    """Create/update serializer for Trivy Hub targets."""

    provider_id = serializers.UUIDField(write_only=True, required=False)
    application_id = serializers.UUIDField(
        write_only=True, required=False, allow_null=True
    )

    class Meta:
        model = TrivyTarget
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "name",
            "description",
            "mode",
            "config",
            "provider_id",
            "application_id",
            "schedule_enabled",
            "schedule_cron",
            "schedule_timezone",
            "next_run_at",
        ]
        extra_kwargs = {
            "id": {"read_only": True},
            "inserted_at": {"read_only": True},
            "updated_at": {"read_only": True},
            "next_run_at": {"read_only": True},
            "name": {"required": False},
            "description": {"required": False},
            "mode": {"required": False},
            "config": {"required": False},
            "schedule_enabled": {"required": False},
            "schedule_cron": {"required": False},
            "schedule_timezone": {"required": False},
        }

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}trivy-targets"

    def validate_name(self, value):
        tenant_id = self.context.get("tenant_id")
        queryset = TrivyTarget.objects.filter(tenant_id=tenant_id, name=value)
        if self.instance:
            queryset = queryset.exclude(pk=self.instance.pk)
        if queryset.exists():
            raise ValidationError("A target with this name already exists.")
        return value

    def _sync_branch_name(self, attrs, mode) -> None:
        """Keep a Git target's branch in its name (``<name> @ <branch>``).

        The name is what lists, reports, exports and scan names show, so it
        carries the branch. Changing the branch replaces it in the name.
        """
        if mode not in REPOSITORY_URL_MODES or "config" not in attrs:
            return
        name = attrs.get("name") or (self.instance.name if self.instance else "")
        if not name:
            return
        old_branch = (
            (self.instance.config or {}).get("branch") if self.instance else ""
        ) or ""
        new_branch = (attrs["config"] or {}).get("branch") or ""
        synced = name_for_branch(name, new_branch, old_branch)
        if synced == name:
            return
        queryset = TrivyTarget.objects.filter(
            tenant_id=self.context.get("tenant_id"), name=synced
        )
        if self.instance:
            queryset = queryset.exclude(pk=self.instance.pk)
        if queryset.exists():
            raise ValidationError(
                {"name": f"A target named '{synced}' already exists."}
            )
        attrs["name"] = synced

    def validate_mode(self, value):
        if not is_valid_trivy_mode(value):
            raise ValidationError(
                "mode must be one of: iac, image, fs, rootfs, repo, sbom, k8s, sast."
            )
        return value

    def validate_provider_id(self, value):
        tenant_id = self.context.get("tenant_id")
        provider = Provider.objects.filter(tenant_id=tenant_id, id=value).first()
        if provider is None:
            raise ValidationError("Unknown provider ID for this tenant.")
        return value

    def validate_application_id(self, value):
        if value is None:
            return value
        tenant_id = self.context.get("tenant_id")
        if not AppSecApplication.objects.filter(tenant_id=tenant_id, id=value).exists():
            raise ValidationError("Unknown application ID for this tenant.")
        return value

    def validate_schedule_timezone(self, value):
        try:
            return validate_timezone(value)
        except CustodianScheduleError as exc:
            raise ValidationError(str(exc)) from exc

    def validate(self, attrs):
        attrs = super().validate(attrs)
        mode = attrs.get("mode")
        if mode is None and self.instance is not None:
            mode = self.instance.mode
        config = attrs.get("config")
        if config is None and self.instance is not None:
            config = self.instance.config
        if mode is not None:
            # A schedule-only edit keeps scanners saved before validation.
            strict = "config" in attrs or "mode" in attrs
            try:
                attrs["config"] = validate_target_config(mode, config, strict=strict)
            except TrivyHubError as exc:
                raise ValidationError({"config": scrub_engine_text(str(exc))}) from exc

        provider_id = attrs.get("provider_id")
        provider = None
        tenant_id = self.context.get("tenant_id")
        if provider_id is not None:
            provider = Provider.objects.filter(
                tenant_id=tenant_id, id=provider_id
            ).first()
        elif self.instance is not None:
            provider = self.instance.provider
        if provider is not None and mode is not None:
            try:
                assert_provider_matches_mode(provider, mode, attrs.get("config"))
            except TrivyHubError as exc:
                raise ValidationError(
                    {"provider_id": scrub_engine_text(str(exc))}
                ) from exc

        if self.instance is None:
            if not attrs.get("name"):
                raise ValidationError({"name": "This field is required."})
            if not mode:
                raise ValidationError({"mode": "This field is required."})
            if provider_id is None:
                raise ValidationError({"provider_id": "This field is required."})

        self._sync_branch_name(attrs, mode)

        schedule_enabled = attrs.get("schedule_enabled")
        if schedule_enabled is None and self.instance is not None:
            schedule_enabled = self.instance.schedule_enabled
        schedule_cron = attrs.get("schedule_cron")
        if schedule_cron is None and self.instance is not None:
            schedule_cron = self.instance.schedule_cron
        if schedule_enabled:
            if not schedule_cron:
                raise ValidationError(
                    {"schedule_cron": "Required when the schedule is enabled."}
                )
            try:
                from cloudsneeker_api.services.custodian_schedule import (
                    parse_cron_fields,
                )

                parse_cron_fields(schedule_cron)
            except CustodianScheduleError as exc:
                raise ValidationError({"schedule_cron": str(exc)}) from exc
        return attrs

    def create(self, validated_data):
        provider_id = validated_data.pop("provider_id")
        tenant_id = self.context["tenant_id"]
        provider = Provider.objects.get(tenant_id=tenant_id, id=provider_id)
        target = TrivyTarget.objects.create(
            tenant_id=tenant_id,
            provider=provider,
            **validated_data,
        )
        try:
            return sync_target_schedule(target)
        except TrivyScheduleError as exc:
            raise ValidationError({"schedule_cron": str(exc)}) from exc

    def update(self, instance, validated_data):
        provider_id = validated_data.pop("provider_id", None)
        if provider_id is not None:
            provider = Provider.objects.get(
                tenant_id=self.context["tenant_id"], id=provider_id
            )
            instance.provider = provider
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        try:
            return sync_target_schedule(instance)
        except TrivyScheduleError as exc:
            raise ValidationError({"schedule_cron": str(exc)}) from exc


ENGINE_LABELS = {"trivy": "scanner", "opengrep": "code analyzer"}


class TrivyRunSerializer(RLSSerializer):
    """Read serializer for Trivy Hub runs."""

    target_id = serializers.UUIDField(source="target.id", read_only=True)
    target_name = serializers.CharField(source="target.name", read_only=True)
    target_mode = serializers.CharField(source="target.mode", read_only=True)
    provider_id = serializers.UUIDField(source="provider.id", read_only=True)
    provider_uid = serializers.CharField(source="provider.uid", read_only=True)
    status = serializers.SerializerMethodField()

    class Meta:
        model = TrivyRun
        fields = [
            "id",
            "inserted_at",
            "updated_at",
            "target_id",
            "target_name",
            "target_mode",
            "provider_id",
            "provider_uid",
            "status",
            "trigger",
            "started_at",
            "finished_at",
            "scan_id",
            "summary",
            "output",
            "error",
            "error_class",
            "engine",
            "engine_version",
            "profile_ref",
            "options",
            "command",
            "exit_code",
            "stderr_tail",
            "duration_ms",
            "attempts",
            "database",
            "coverage",
            "stats",
            "cancel_requested_at",
            "has_artifact",
            "archived_at",
            "branch",
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}trivy-runs"

    has_artifact = serializers.SerializerMethodField()
    branch = serializers.SerializerMethodField()

    def get_branch(self, obj: TrivyRun) -> str:
        return run_branch(obj.summary, obj.output, obj.options)

    def get_has_artifact(self, obj: TrivyRun) -> bool:
        return bool(obj.artifact_path)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["error"] = scrub_engine_text(data.get("error"))
        # Engine names stay out of client-visible text (brand rule).
        data["stderr_tail"] = scrub_engine_text(data.get("stderr_tail"))
        data["command"] = [
            scrub_engine_text(str(item)) for item in (data.get("command") or [])
        ]
        data["engine"] = ENGINE_LABELS.get(data.get("engine") or "", "")
        return data

    def get_status(self, obj: TrivyRun) -> str:
        return effective_run_status(
            obj.status, obj.summary, getattr(obj, "linked_scan_state", None)
        )
